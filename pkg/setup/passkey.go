package setup

import (
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// PasskeyRequest is one registration of the person's portal passkey: the
// link they open, and the request their answer is verified against.
type PasskeyRequest struct {
	r setuprun.ContractPasskeyRequest
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
	return passkeyRequest(setuprun.ContractPasskeyRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName, label))
}

// passkeyRequest is the service's registration request, or its error.
func passkeyRequest(r setuprun.ContractPasskeyRequest, err error) (PasskeyRequest, error) {
	return PasskeyRequest{r: r}, err
}

// Verify checks the code the registration page shows
// (basalt-passkey.1....) against the request and the portal, and returns
// the passkey Run registers.
func (r PasskeyRequest) Verify(code string) (Passkey, error) {
	return verifiedPasskey(r.r.Verify(code))
}

// verifiedPasskey is the service's verified passkey, or its error.
func verifiedPasskey(p setuprun.ContractPasskey, err error) (Passkey, error) {
	return Passkey{p: p}, err
}

// Passkey is a verified portal passkey registration. Only
// PasskeyRequest.Verify makes one.
type Passkey struct {
	p setuprun.ContractPasskey
}

// RegisteredPasskey is a passkey a run stored.
type RegisteredPasskey struct {
	CredentialID []byte
	RPID         string
	Origin       string
	Label        string
}
