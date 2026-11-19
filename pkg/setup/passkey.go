package setup

import (
	"context"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
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

// registerPasskey stores the person's passkey when the database has no
// active portal passkey, or in.AddPasskey asks for another (step 7).
func registerPasskey(ctx context.Context, conn *pgx.Conn, in RunInput) (*RegisteredPasskey, error) {
	need, err := setuprun.PasskeyNeeded(ctx, conn, in.AddPasskey)
	if err != nil || !need {
		return nil, err
	}
	if in.Passkey == nil {
		return nil, errors.New("no passkey was given")
	}
	pk, err := in.Passkey(ctx)
	if err != nil {
		return nil, err
	}
	if pk.cred.PublicKey == nil {
		return nil, errors.New("the passkey was not verified")
	}
	if err := guard.RegisterPasskey(ctx, conn, pk.cred, pk.label); err != nil {
		return nil, err
	}
	return &RegisteredPasskey{CredentialID: append([]byte(nil), pk.cred.ID...), RPID: pk.cred.Relying.RPID, Origin: pk.cred.Relying.Origin, Label: pk.label}, nil
}
