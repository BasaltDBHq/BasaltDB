package setuprun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// MaxPasskeyLabel is the registration request's label limit in bytes.
const MaxPasskeyLabel = 64

// NewRegistrationRequest draws a passkey registration request from rnd
// (crypto/rand.Reader outside tests) for a passkey named label on
// database: the picker shows "BasaltDB · <database>", or label when that
// is too long.
func NewRegistrationRequest(rnd io.Reader, label, database string) (passkey.RegistrationRequest, error) {
	display := "BasaltDB · " + database
	if len(display) > MaxPasskeyLabel {
		display = label
	}
	return passkey.NewRegistrationRequest(rnd, label, display)
}

// VerifyRegistrationCode checks a pasted registration code against req.
func VerifyRegistrationCode(code string, req passkey.RegistrationRequest, rp passkey.Relying) (passkey.Credential, error) {
	if strings.TrimSpace(code) == "" {
		return passkey.Credential{}, errors.New("no passkey code given")
	}
	resp, err := passkey.ParseRegistrationResponse(code)
	if err != nil {
		return passkey.Credential{}, err
	}
	return passkey.VerifyRegistration(req, resp, rp)
}

// HasPasskeyFor reports whether an active passkey of this database belongs
// to origin. A passkey signs only on the origin it was registered on, so
// one for the local pages does not count for the portal.
func HasPasskeyFor(ctx context.Context, q Querier, origin string) (bool, error) {
	var ok bool
	// Plain SQL: a presence check on the admin connection.
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM basalt_meta.passkeys WHERE origin = $1 AND revoked_at IS NULL)`, origin).Scan(&ok)
	return ok, err
}

// PasskeyNeeded is whether the setup registers a portal passkey (step 7):
// when no active one is registered, or add asks for another. Before the
// setup ran, a database without the guard has none.
func PasskeyNeeded(ctx context.Context, q Querier, add bool) (bool, error) {
	if add {
		return true, nil
	}
	has, err := HasPasskeyFor(ctx, q, passkey.Production.Origin)
	if isUndefinedTable(err) {
		return true, nil
	}
	return !has, err
}

// PasskeyFailed is the refusal when the setup ran and its passkey step
// failed with err.
func PasskeyFailed(p setupcode.Payload, err error) error {
	return &RefusalError{Code: CodePasskeyMissing, Err: err, Message: fmt.Sprintf("the setup ran but no passkey was registered: %s. Ask %s for a new code; running it registers the passkey",
		err.Error(), AgentWord(p))}
}

// LocalRelying is the relying party of the setup page served at origin on
// this computer.
func LocalRelying(origin string) (passkey.Relying, error) { return passkey.Local(origin) }

// RegistrationRequestFor rebuilds the registration request the setup page
// was handed, from the fields it sent back.
func RegistrationRequestFor(challenge, userID []byte, userName, displayName string) (passkey.RegistrationRequest, error) {
	return passkey.RegistrationRequestFor(challenge, userID, userName, displayName)
}

// VerifyRegistration checks the browser's registration response against req
// and returns the credential to record.
func VerifyRegistration(req passkey.RegistrationRequest, resp passkey.RegistrationResponse, rp passkey.Relying) (passkey.Credential, error) {
	return passkey.VerifyRegistration(req, resp, rp)
}
