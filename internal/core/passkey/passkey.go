// Package passkey verifies WebAuthn ES256 (P-256) passkey registrations and
// assertions the way basalt_meta.submit_approval does in Postgres
// (CONTRACT.md, Approvals). Postgres is the only check that counts; this Go
// mirror lets basalt init verify a registration before storing it, and is
// the oracle the guard's PL/pgSQL verifier is tested against.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// The hosted relying party (owner decisions, Decided Nov 12): RP ID
// basaltvault.app, fixed for good since registered passkeys depend on it,
// and the portal's origin.
const (
	RPID   = "basaltvault.app"
	Origin = links.Portal
)

// localRPID is the development relying party: the pages served from
// http://localhost:<port>.
const localRPID = "localhost"

// Relying is the relying party a passkey belongs to: the RP ID hashed into
// authenticator data and the exact origin in client data.
type Relying struct {
	RPID   string
	Origin string
}

// Production is the portal: RP ID basaltvault.app, origin
// https://portal.basaltvault.app.
var Production = Relying{RPID: RPID, Origin: Origin}

// Local returns the development relying party for the pages served at origin,
// which must be http://localhost:<port>.
func Local(origin string) (Relying, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return Relying{}, fmt.Errorf("local origin: %w", err)
	}
	if u.Scheme != "http" || u.Hostname() != localRPID || u.Port() == "" || u.Path != "" || u.String() != origin {
		return Relying{}, fmt.Errorf("local origin must be http://localhost:<port>, got %q", origin)
	}
	if _, err := strconv.ParseUint(u.Port(), 10, 16); err != nil {
		return Relying{}, fmt.Errorf("local origin port: %w", err)
	}
	return Relying{RPID: localRPID, Origin: origin}, nil
}

// ErrRejected wraps every reason a registration or assertion is refused.
var ErrRejected = errors.New("passkey rejected")

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Authenticator data flags (WebAuthn §6.1).
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

// Authenticator data layout (WebAuthn §6.1, §6.5.1).
const (
	rpIDHashLen     = 32
	flagsOffset     = rpIDHashLen
	counterOffset   = flagsOffset + 1
	counterLen      = 4
	authDataMinLen  = counterOffset + counterLen
	aaguidLen       = 16
	credIDLenOffset = authDataMinLen + aaguidLen
	credIDLenLen    = 2
	credIDOffset    = credIDLenOffset + credIDLenLen
)

// Client data types (WebAuthn §5.8.1).
const (
	typeCreate = "webauthn.create"
	typeGet    = "webauthn.get"
)

// authData is the parsed fixed part of authenticator data.
type authData struct {
	rpIDHash     []byte
	flags        byte
	counter      uint32
	credentialID []byte // set when the AT flag is
}

func parseAuthData(raw []byte) (authData, error) {
	if len(raw) < authDataMinLen {
		return authData{}, rejected("authenticator data too short")
	}
	ad := authData{
		rpIDHash: raw[:rpIDHashLen],
		flags:    raw[flagsOffset],
		counter:  binary.BigEndian.Uint32(raw[counterOffset:authDataMinLen]),
	}
	if ad.flags&flagAttested == 0 {
		return ad, nil
	}
	if len(raw) < credIDOffset {
		return authData{}, rejected("attested credential data too short")
	}
	n := int(binary.BigEndian.Uint16(raw[credIDLenOffset:credIDOffset]))
	if len(raw) < credIDOffset+n {
		return authData{}, rejected("attested credential id too short")
	}
	ad.credentialID = raw[credIDOffset : credIDOffset+n]
	return ad, nil
}

// check applies the checks registration and assertion share: the RP ID hash
// and the user present and user verified flags.
func (ad authData) check(rp Relying) error {
	want := sha256.Sum256([]byte(rp.RPID))
	if !bytes.Equal(ad.rpIDHash, want[:]) {
		return rejected("rpIdHash mismatch")
	}
	if ad.flags&flagUserPresent == 0 || ad.flags&flagUserVerified == 0 {
		return rejected("user presence and verification required")
	}
	return nil
}

// clientData is the part of clientDataJSON the checks read.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func checkClientData(raw []byte, wantType string, challenge []byte, rp Relying) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return rejected("client data is not JSON")
	}
	if cd.Type != wantType || cd.Challenge != Bytes(challenge).String() || cd.Origin != rp.Origin {
		return rejected("client data does not match the request")
	}
	return nil
}

// Credential is a registered passkey: what basalt_meta.passkeys stores.
type Credential struct {
	ID        []byte
	PublicKey *ecdsa.PublicKey
	SignCount uint32
	Relying   Relying
	// UserHandle is the WebAuthn user id the passkey was created with (nil
	// when unknown); the forget page signals with it.
	UserHandle []byte
}

// coordLen is the byte length of a P-256 coordinate.
const coordLen = 32

// XY returns the public key's coordinates, 32 bytes each, as stored in
// basalt_meta.passkeys.
func (c Credential) XY() (x, y []byte, err error) {
	raw, err := c.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		return nil, nil, fmt.Errorf("public key: %w", err)
	}
	return raw[1 : 1+coordLen], raw[1+coordLen:], nil
}

// PublicKeyFromXY rebuilds a P-256 public key from stored coordinates.
func PublicKeyFromXY(x, y []byte) (*ecdsa.PublicKey, error) {
	if len(x) != coordLen || len(y) != coordLen {
		return nil, rejected("coordinates must be %d bytes", coordLen)
	}
	const uncompressed = 0x04
	raw := append(append([]byte{uncompressed}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, rejected("not a P-256 point")
	}
	return pub, nil
}

// Assertion is what navigator.credentials.get returns, as relayed.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte // ASN.1 DER
}

// VerifyAssertion checks an assertion over challenge the way
// basalt_meta.submit_approval does, and returns the new signature counter
// to store.
func VerifyAssertion(cred Credential, challenge []byte, a Assertion) (uint32, error) {
	if !bytes.Equal(a.CredentialID, cred.ID) {
		return 0, rejected("assertion is for another passkey")
	}
	if err := checkClientData(a.ClientDataJSON, typeGet, challenge, cred.Relying); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(a.AuthenticatorData)
	if err != nil {
		return 0, err
	}
	if err := ad.check(cred.Relying); err != nil {
		return 0, err
	}
	// Some authenticators never count: 0 is accepted while the stored count is 0.
	if (ad.counter != 0 || cred.SignCount != 0) && ad.counter <= cred.SignCount {
		return 0, rejected("signature counter did not increase (cloned authenticator or replay)")
	}
	cdh := sha256.Sum256(a.ClientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, a.AuthenticatorData...), cdh[:]...))
	if !ecdsa.VerifyASN1(cred.PublicKey, digest[:], a.Signature) {
		return 0, rejected("bad passkey signature")
	}
	return ad.counter, nil
}
