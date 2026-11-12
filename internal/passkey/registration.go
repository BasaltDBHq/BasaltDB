package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Code prefixes (CONTRACT.md, Approvals, Codes).
const (
	// RegistrationRequestPrefix starts the URL fragment of the
	// registration page: <base>/passkeys/register#1.<request>.
	RegistrationRequestPrefix = "1."
	// RegistrationResponsePrefix starts the code the registration page
	// outputs and basalt init reads.
	RegistrationResponsePrefix = "basalt-passkey.1."
)

// Sizes of the registration request's random fields.
const (
	challengeLen = 32
	userIDLen    = 16
	maxLabelLen  = 64
)

// AlgES256 is the COSE algorithm id of ES256, the only one accepted.
const AlgES256 = -7

// RegistrationRequest is what basalt init sends the registration page.
type RegistrationRequest struct {
	Challenge   Bytes  `json:"challenge"`
	UserID      Bytes  `json:"userId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
}

// NewRegistrationRequest draws a fresh challenge and user id from rnd
// (crypto/rand.Reader outside tests).
func NewRegistrationRequest(rnd io.Reader, userName, displayName string) (RegistrationRequest, error) {
	req := RegistrationRequest{
		Challenge:   make([]byte, challengeLen),
		UserID:      make([]byte, userIDLen),
		UserName:    userName,
		DisplayName: displayName,
	}
	if _, err := io.ReadFull(rnd, req.Challenge); err != nil {
		return RegistrationRequest{}, fmt.Errorf("registration challenge: %w", err)
	}
	if _, err := io.ReadFull(rnd, req.UserID); err != nil {
		return RegistrationRequest{}, fmt.Errorf("registration user id: %w", err)
	}
	return req, req.validate()
}

func (r RegistrationRequest) validate() error {
	if len(r.Challenge) != challengeLen || len(r.UserID) != userIDLen {
		return rejected("registration request needs a %d-byte challenge and a %d-byte user id", challengeLen, userIDLen)
	}
	for _, label := range []string{r.UserName, r.DisplayName} {
		if label == "" || len(label) > maxLabelLen || !utf8.ValidString(label) {
			return rejected("registration labels must be 1 to %d bytes of UTF-8", maxLabelLen)
		}
	}
	return nil
}

// Fragment returns the URL fragment (without '#') for the registration page.
func (r RegistrationRequest) Fragment() (string, error) {
	return EncodeCode(RegistrationRequestPrefix, r)
}

// ParseRegistrationRequest decodes a registration page fragment, with or
// without the leading '#'.
func ParseRegistrationRequest(fragment string) (RegistrationRequest, error) {
	var r RegistrationRequest
	if err := DecodeCode(RegistrationRequestPrefix, strings.TrimPrefix(fragment, "#"), &r); err != nil {
		return RegistrationRequest{}, err
	}
	return r, r.validate()
}

// RegistrationResponse is what the registration page outputs.
type RegistrationResponse struct {
	CredentialID       Bytes `json:"credentialId"`
	ClientDataJSON     Bytes `json:"clientDataJson"`
	AuthenticatorData  Bytes `json:"authenticatorData"`
	PublicKey          Bytes `json:"publicKey"`
	PublicKeyAlgorithm int   `json:"publicKeyAlgorithm"`
	// PRFSupported is whether the authenticator reported the prf extension as
	// enabled at registration. Optional and unused until the vault channel's
	// Phase 1b; no prf output is ever part of the code.
	PRFSupported bool `json:"prfSupported,omitempty"`
}

// Code returns the text the person copies: basalt-passkey.1.<base64url(json)>.
func (r RegistrationResponse) Code() (string, error) {
	return EncodeCode(RegistrationResponsePrefix, r)
}

// ParseRegistrationResponse decodes a pasted registration code. Surrounding
// whitespace is ignored.
func ParseRegistrationResponse(code string) (RegistrationResponse, error) {
	var r RegistrationResponse
	if err := DecodeCode(RegistrationResponsePrefix, strings.TrimSpace(code), &r); err != nil {
		return RegistrationResponse{}, err
	}
	return r, nil
}

// VerifyRegistration checks a registration response against the request
// basalt init made and the relying party, and returns the credential to
// store. Attestation is "none", so the checks are those WebAuthn §7.1 makes
// without an attestation statement: client data type, challenge and origin;
// RP ID hash; user present and verified; the attested credential id; an
// ES256 P-256 key.
func VerifyRegistration(req RegistrationRequest, resp RegistrationResponse, rp Relying) (Credential, error) {
	if resp.PublicKeyAlgorithm != AlgES256 {
		return Credential{}, rejected("algorithm %d, want ES256 (%d)", resp.PublicKeyAlgorithm, AlgES256)
	}
	if err := checkClientData(resp.ClientDataJSON, typeCreate, req.Challenge, rp); err != nil {
		return Credential{}, err
	}
	ad, err := parseAuthData(resp.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	if err := ad.check(rp); err != nil {
		return Credential{}, err
	}
	if ad.flags&flagAttested == 0 || !bytes.Equal(ad.credentialID, resp.CredentialID) || len(resp.CredentialID) == 0 {
		return Credential{}, rejected("attested credential id does not match")
	}
	key, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return Credential{}, rejected("public key is not SubjectPublicKeyInfo DER")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return Credential{}, rejected("public key is not P-256")
	}
	return Credential{ID: resp.CredentialID, PublicKey: pub, SignCount: ad.counter, Relying: rp, UserHandle: req.UserID}, nil
}

// maxCodeLen bounds a pasted or linked code before decoding.
const maxCodeLen = 64 << 10

// EncodeCode returns prefix followed by the base64url JSON of v: the shape of
// every approval and passkey code (CONTRACT.md, Approvals, Codes).
func EncodeCode(prefix string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode %s code: %w", prefix, err)
	}
	return prefix + Bytes(raw).String(), nil
}

// DecodeCode reverses EncodeCode, refusing unknown fields and oversized codes.
func DecodeCode(prefix, code string, v any) error {
	payload, ok := strings.CutPrefix(code, prefix)
	if !ok {
		return rejected("code must start with %q", prefix)
	}
	if len(payload) > maxCodeLen {
		return rejected("code longer than %d bytes", maxCodeLen)
	}
	raw, err := DecodeBase64URL(payload)
	if err != nil {
		return rejected("code is not base64url")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return rejected("code payload: %v", err)
	}
	return nil
}
