package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// PasskeyRequest is one registration of the person's portal passkey: the
// link they open, and the request their answer is verified against.
type PasskeyRequest struct {
	req   passkey.RegistrationRequest
	label string
}

// NewPasskeyRequest draws a registration request from random
// (crypto/rand.Reader, or a source the caller can draw again) for a
// passkey named label on database. The label is at most 64 bytes.
func NewPasskeyRequest(random io.Reader, label, database string) (PasskeyRequest, error) {
	req, err := setuprun.NewRegistrationRequest(random, label, database)
	if err != nil {
		return PasskeyRequest{}, err
	}
	return PasskeyRequest{req: req, label: label}, nil
}

// PasskeyChallenge is a registration request a caller made and showed the
// browser itself, such as a service that sends a page the challenge and
// keeps nothing: the request is rebuilt from it to verify the browser's
// answer.
type PasskeyChallenge struct {
	// Challenge is the 32 random bytes the browser signs.
	Challenge []byte
	// UserID is the 16 random bytes the browser keeps as the passkey's
	// user handle; Run stores it with the passkey.
	UserID []byte
	// UserName and DisplayName are the labels the passkey picker showed,
	// 1 to 64 bytes of UTF-8 each.
	UserName    string
	DisplayName string
}

// PasskeyRequestFor rebuilds the registration request of a challenge the
// caller issued, for a passkey named label (1 to 64 bytes). Verify then
// checks the browser's answer against that challenge and user id. The
// request copies the challenge's bytes.
func PasskeyRequestFor(c PasskeyChallenge, label string) (PasskeyRequest, error) {
	if label == "" || len(label) > setuprun.MaxPasskeyLabel || !utf8.ValidString(label) {
		return PasskeyRequest{}, fmt.Errorf("the passkey label must be 1 to %d bytes of UTF-8", setuprun.MaxPasskeyLabel)
	}
	req, err := setuprun.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	if err != nil {
		return PasskeyRequest{}, err
	}
	return PasskeyRequest{req: req, label: label}, nil
}

// Link is the portal's registration page for the request
// (https://portal.basaltvault.app/passkeys/register#1.<request>).
func (r PasskeyRequest) Link() (string, error) {
	frag, err := r.req.Fragment()
	if err != nil {
		return "", err
	}
	return links.Register(passkey.Production.Origin) + "#" + frag, nil
}

// Verify checks the code the registration page shows
// (basalt-passkey.1....) against the request and the portal, and returns
// the passkey Run registers.
func (r PasskeyRequest) Verify(code string) (Passkey, error) {
	cred, err := setuprun.VerifyRegistrationCode(code, r.req, passkey.Production)
	if err != nil {
		return Passkey{}, err
	}
	return Passkey{cred: cred, label: r.label}, nil
}

// Passkey is a verified portal passkey registration. Only
// PasskeyRequest.Verify makes one.
type Passkey struct {
	cred  passkey.Credential
	label string
}

// RegisteredPasskey is a passkey a run stored.
type RegisteredPasskey struct {
	CredentialID []byte
	RPID         string
	Origin       string
	Label        string
}

func (p *Passkey) verified() bool { return p.cred.PublicKey != nil }

func (p *Passkey) registered() *RegisteredPasskey {
	return &RegisteredPasskey{CredentialID: append([]byte(nil), p.cred.ID...), RPID: p.cred.Relying.RPID, Origin: p.cred.Relying.Origin, Label: p.label}
}

// registerInTx registers the person's verified passkey in the setup's
// transaction.
func registerInTx(ctx context.Context, tx pgx.Tx, pk *Passkey) (*RegisteredPasskey, error) {
	if err := guard.RegisterPasskey(ctx, tx, pk.cred, pk.label); err != nil {
		return nil, err
	}
	return pk.registered(), nil
}

// requirePasskey refuses PASSKEY_REQUIRED, in the setup's transaction
// before its script runs, when the database needs the person's passkey and
// none was given: nothing changed.
func requirePasskey(ctx context.Context, tx setuprun.Querier, add bool) error {
	need, err := setuprun.PasskeyNeeded(ctx, store, tx, add)
	if err != nil {
		return err
	}
	if need {
		return &setuprun.SetuprunRefusalError{Code: CodePasskeyRequired, Message: "this setup needs the person's portal passkey, and none was given"}
	}
	return nil
}

// askPasskey is the laptop's passkey step, after the setup committed (step
// 7): it asks for the person's passkey and stores it when the database has
// no active portal passkey, or in.AddPasskey asks for another.
func askPasskey(ctx context.Context, conn *pgx.Conn, in RunInput) (*RegisteredPasskey, error) {
	need, err := setuprun.PasskeyNeeded(ctx, store, pgquerier.Neutralize(conn), in.AddPasskey)
	if err != nil || !need {
		return nil, err
	}
	pk, err := in.AskPasskey(ctx)
	if err != nil {
		return nil, err
	}
	if !pk.verified() {
		return nil, errors.New("the passkey was not verified")
	}
	if err := guard.RegisterPasskey(ctx, conn, pk.cred, pk.label); err != nil {
		return nil, err
	}
	return pk.registered(), nil
}
