package setup

import (
	"context"
	"errors"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// MaxPasskeyLabel is the registration request's label limit in bytes.
const MaxPasskeyLabel = passkey.MaxLabelLen

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

// PasskeyNeeded is whether the setup needs the person's portal passkey:
// when no active one is registered. Before the
// setup ran, a database without the guard has none.
func PasskeyNeeded(ctx context.Context, b SetuprunBackend, q Querier) (bool, error) {
	has, err := b.HasPasskeyFor(ctx, q, passkey.Production.Origin)
	if b.UndefinedTable(err) {
		return true, nil
	}
	return !has, err
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
