// Package passkeytest is a software WebAuthn authenticator holding an ES256
// credential. It produces the exact byte layouts a platform authenticator
// and navigator.credentials return, so passkey, approval and guard tests can
// register and sign without a browser.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Authenticator flags.
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagAT = 0x40
	// FlagsUPUV is what a platform passkey sets for a verified assertion.
	FlagsUPUV = FlagUP | FlagUV
)

const (
	credentialIDLen = 16
	aaguidLen       = 16
)

// Authenticator is one software passkey for one relying party.
type Authenticator struct {
	ID      []byte
	Key     *ecdsa.PrivateKey
	Counter uint32
	Relying passkey.Relying
}

// New creates a passkey for rp with a random key and credential id.
func New(rp passkey.Relying) (*Authenticator, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	id := make([]byte, credentialIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("credential id: %w", err)
	}
	return &Authenticator{ID: id, Key: k, Relying: rp}, nil
}

// Credential is what basalt init stores for this passkey.
func (a *Authenticator) Credential() passkey.Credential {
	return passkey.Credential{ID: a.ID, PublicKey: &a.Key.PublicKey, SignCount: 0, Relying: a.Relying}
}

func (a *Authenticator) clientData(typ string, challenge []byte) []byte {
	cd, err := json.Marshal(map[string]any{
		"type": typ, "challenge": passkey.Bytes(challenge).String(), "origin": a.Relying.Origin, "crossOrigin": false,
	})
	if err != nil {
		panic(err) // a map of strings and a bool always marshals
	}
	return cd
}

func (a *Authenticator) authData(flags byte) []byte {
	rp := sha256.Sum256([]byte(a.Relying.RPID))
	ad := append(rp[:], flags)
	return binary.BigEndian.AppendUint32(ad, a.Counter)
}

// Register answers a registration request the way the registration page
// does: attested credential data in the authenticator data and the SPKI
// public key. Tamper, when set, edits the response before it is returned.
func (a *Authenticator) Register(req passkey.RegistrationRequest, tamper func(*passkey.RegistrationResponse)) (passkey.RegistrationResponse, error) {
	spki, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		return passkey.RegistrationResponse{}, fmt.Errorf("marshal key: %w", err)
	}
	ad := a.authData(FlagsUPUV | FlagAT)
	ad = append(ad, make([]byte, aaguidLen)...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.ID)))
	ad = append(ad, a.ID...)
	resp := passkey.RegistrationResponse{
		CredentialID:       a.ID,
		ClientDataJSON:     a.clientData("webauthn.create", req.Challenge),
		AuthenticatorData:  ad,
		PublicKey:          spki,
		PublicKeyAlgorithm: passkey.AlgES256,
	}
	if tamper != nil {
		tamper(&resp)
	}
	return resp, nil
}

// Sign returns an assertion over challenge with the given flags, bumping the
// counter first like a real authenticator. Tamper, when set, edits the
// authenticator data or client data before signing.
func (a *Authenticator) Sign(challenge []byte, flags byte, tamper func(*passkey.Assertion)) (passkey.Assertion, error) {
	a.Counter++
	as := passkey.Assertion{
		CredentialID:      a.ID,
		AuthenticatorData: a.authData(flags),
		ClientDataJSON:    a.clientData("webauthn.get", challenge),
	}
	if tamper != nil {
		tamper(&as)
	}
	cdh := sha256.Sum256(as.ClientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, as.AuthenticatorData...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		return passkey.Assertion{}, fmt.Errorf("sign: %w", err)
	}
	as.Signature = sig
	return as, nil
}
