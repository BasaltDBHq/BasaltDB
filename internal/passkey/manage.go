package passkey

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
)

// The passkey management page (CONTRACT.md, Passkey management):
// <origin>/passkeys/#1.<request>. It checks which passkeys a device can
// still produce, and asks a device's password manager to forget removed
// ones.
const (
	// ManagePath is the page on the passkey's origin.
	ManagePath = "/passkeys/"
	// ManageRequestPrefix starts the page's URL fragment.
	ManageRequestPrefix = "1."
	// CheckResponsePrefix starts the code the page outputs after a check.
	CheckResponsePrefix = "basalt-passkey-check.1."
	// checkChallengePrefix starts the text a check signs. Approval and
	// revert challenges hash a JSON binding text, which never starts with
	// it, so a check signature can never authorize anything.
	checkChallengePrefix = "basalt-passkey-check.1."
)

// Page modes.
const (
	ModeCheck  = "CHECK"
	ModeForget = "FORGET"
)

// maxManaged bounds the passkeys one link carries (the list bound).
const maxManaged = 100

// Labeled is a passkey the page names.
type Labeled struct {
	CredentialID Bytes  `json:"credentialId"`
	Label        string `json:"label"`
}

// CheckRequest asks the page to sign a harmless challenge with each passkey.
type CheckRequest struct {
	Mode        string    `json:"mode"`
	Challenge   Bytes     `json:"challenge"`
	Credentials []Labeled `json:"credentials"`
}

// Removed is a revoked passkey the forget page signals about.
type Removed struct {
	CredentialID Bytes  `json:"credentialId"`
	Label        string `json:"label"`
	UserHandle   Bytes  `json:"userHandle,omitempty"`
}

// ForgetRequest asks the page to tell the device's password manager which
// passkeys are gone (WebAuthn Signal API).
type ForgetRequest struct {
	Mode     string    `json:"mode"`
	Removed  []Removed `json:"removed"`
	Accepted []Bytes   `json:"accepted"`
}

// NewCheckRequest draws a fresh challenge from rnd (crypto/rand.Reader
// outside tests) for the given passkeys, all of one origin.
func NewCheckRequest(rnd io.Reader, creds []Labeled) (CheckRequest, error) {
	if len(creds) == 0 || len(creds) > maxManaged {
		return CheckRequest{}, fmt.Errorf("a check link carries 1 to %d passkeys, got %d", maxManaged, len(creds))
	}
	req := CheckRequest{Mode: ModeCheck, Challenge: make([]byte, challengeLen), Credentials: creds}
	if _, err := io.ReadFull(rnd, req.Challenge); err != nil {
		return CheckRequest{}, fmt.Errorf("check challenge: %w", err)
	}
	return req, nil
}

// ManageURL is the page link for a check or forget request on origin.
func ManageURL(origin string, req any) (string, error) {
	frag, err := EncodeCode(ManageRequestPrefix, req)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(origin, "/") + ManagePath + "#" + frag, nil
}

// CheckChallenge is the WebAuthn challenge a check signs:
// sha256(utf8("basalt-passkey-check.1." + base64url(challenge))).
func CheckChallenge(challenge []byte) []byte {
	sum := sha256.Sum256([]byte(checkChallengePrefix + Bytes(challenge).String()))
	return sum[:]
}

// CheckedAssertion is one passkey the device produced.
type CheckedAssertion struct {
	CredentialID      Bytes `json:"credentialId"`
	AuthenticatorData Bytes `json:"authenticatorData"`
	ClientDataJSON    Bytes `json:"clientDataJson"`
	Signature         Bytes `json:"signature"`
}

// CheckResponse is what the page outputs after a check.
type CheckResponse struct {
	Challenge Bytes              `json:"challenge"`
	Found     []CheckedAssertion `json:"found"`
	Missing   []Bytes            `json:"missing"`
}

// ParseCheckResponse decodes a pasted check code. Surrounding whitespace is
// ignored.
func ParseCheckResponse(code string) (CheckResponse, error) {
	var r CheckResponse
	if err := DecodeCode(CheckResponsePrefix, strings.TrimSpace(code), &r); err != nil {
		return CheckResponse{}, err
	}
	return r, nil
}

// Code returns the text the page shows: basalt-passkey-check.1.<base64url(json)>.
func (r CheckResponse) Code() (string, error) {
	return EncodeCode(CheckResponsePrefix, r)
}

// VerifyCheck returns the ids of creds the response proves present: each
// found assertion must verify against its stored credential over the
// request's check challenge. The counter is not compared, since check
// signatures never reach Postgres and the stored count may lag. A
// response for another request, or an assertion that does not verify, is
// an error: the CLI reports nothing it cannot prove.
func VerifyCheck(req CheckRequest, resp CheckResponse, creds []Credential) (map[string]bool, error) {
	if !bytes.Equal(req.Challenge, resp.Challenge) {
		return nil, rejected("the code answers another check link")
	}
	challenge := CheckChallenge(req.Challenge)
	found := make(map[string]bool, len(resp.Found))
	for _, a := range resp.Found {
		cred, ok := findCredential(creds, a.CredentialID)
		if !ok {
			return nil, rejected("the code names a passkey the link did not ask for")
		}
		cred.SignCount = 0
		if _, err := VerifyAssertion(cred, challenge, Assertion{
			CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData,
			ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
		}); err != nil {
			return nil, err
		}
		found[Bytes(cred.ID).String()] = true
	}
	return found, nil
}

func findCredential(creds []Credential, id []byte) (Credential, bool) {
	for _, c := range creds {
		if bytes.Equal(c.ID, id) {
			return c, true
		}
	}
	return Credential{}, false
}
