package setup

import (
	"fmt"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// PasskeyRequest is one registration of the person's portal passkey: the
// link they open, and the request their answer is verified against.
type PasskeyRequest struct {
	req   passkey.RegistrationRequest
	label string
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
