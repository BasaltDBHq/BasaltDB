package vaulttest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/coder/websocket"
)

// Wire constants of CONTRACT.md, Vault channel.
const (
	// PortalOrigin is the only Origin the Vault accepts on a page socket.
	PortalOrigin = "https://portal.basaltvault.app"
	// EngineKeyHeader carries the engine's signing key SPKI on the engine socket.
	EngineKeyHeader = "basalt-engine-key"
	// AuthContext starts the input the engine signs to answer CHALLENGE.
	AuthContext = "basalt-vault-engine.1\n"

	// Version is the only version byte and AUTH version.
	Version byte = 0x01
	// TypeRoute is the type byte of a ROUTE message on the engine socket.
	TypeRoute byte = 0x10

	// SIDLen is the size of a session id: 16 random bytes per page socket.
	SIDLen = 16
	// LinkTokenLen is the size of a decoded link token.
	LinkTokenLen = 16
	// ChallengeLen is the size of a CHALLENGE.
	ChallengeLen = 32
	// EngineIDLen is the number of bytes of sha256(SPKI) that make an engine id.
	EngineIDLen = 16
	// SPKILen is the size of a P-256 SubjectPublicKeyInfo with an uncompressed point.
	SPKILen = 91
	// SigLen is an ECDSA P-256 signature as r || s.
	SigLen = 64
	// routeHeaderLen is version, type and sid in front of a ROUTE payload.
	routeHeaderLen = 2 + SIDLen

	// MaxControl is the largest control (text) message, 4 KiB.
	MaxControl = 4 << 10
	// MaxFrame is the largest page message: a frame of 32 768 padded bytes, 2 of header, 16 of tag.
	MaxFrame = 32786
	// MaxRoute is the largest ROUTE message: a frame plus its 18-byte header.
	MaxRoute = MaxFrame + routeHeaderLen
	// MaxExpiryAhead is how far ahead REGISTER_LINK may set expiresAt.
	MaxExpiryAhead = 24*time.Hour + 5*time.Minute
	// ChallengeTTL is how long a CHALLENGE stays valid.
	ChallengeTTL = 30 * time.Second
	// MinLinksPerEngine is the number of live links the Vault must accept per engine.
	MinLinksPerEngine = 1000
	// maxRef is the largest ref, 2^53 - 1, so it survives a JSON number in a browser.
	maxRef = 1<<53 - 1
)

// Close codes, registry api/mcp/vault/close-codes.json.
const (
	CloseNormal             websocket.StatusCode = 1000
	CloseProtocol           websocket.StatusCode = 4000
	CloseUnsupportedVersion websocket.StatusCode = 4001
	CloseAuthFailed         websocket.StatusCode = 4002
	CloseReplaced           websocket.StatusCode = 4003
	CloseLinkUnknown        websocket.StatusCode = 4004
	CloseEngineOffline      websocket.StatusCode = 4005
	CloseLinkRefused        websocket.StatusCode = 4006
	CloseHandshakeFailed    websocket.StatusCode = 4007
	CloseFrameInvalid       websocket.StatusCode = 4008
	CloseTooLarge           websocket.StatusCode = 4009
	CloseRateLimited        websocket.StatusCode = 4010
	CloseSessionLimit       websocket.StatusCode = 4011
	CloseTimeout            websocket.StatusCode = 4012
	CloseEngineRevoked      websocket.StatusCode = 4013
	CloseEngineShutdown     websocket.StatusCode = 4014
)

// CloseNames maps every registry code to its name, the close reason.
var CloseNames = map[int]string{
	int(CloseProtocol):           "PROTOCOL",
	int(CloseUnsupportedVersion): "UNSUPPORTED_VERSION",
	int(CloseAuthFailed):         "AUTH_FAILED",
	int(CloseReplaced):           "REPLACED",
	int(CloseLinkUnknown):        "LINK_UNKNOWN",
	int(CloseEngineOffline):      "ENGINE_OFFLINE",
	int(CloseLinkRefused):        "LINK_REFUSED",
	int(CloseHandshakeFailed):    "HANDSHAKE_FAILED",
	int(CloseFrameInvalid):       "FRAME_INVALID",
	int(CloseTooLarge):           "TOO_LARGE",
	int(CloseRateLimited):        "RATE_LIMITED",
	int(CloseSessionLimit):       "SESSION_LIMIT",
	int(CloseTimeout):            "TIMEOUT",
	int(CloseEngineRevoked):      "ENGINE_REVOKED",
	int(CloseEngineShutdown):     "ENGINE_SHUTDOWN",
}

// sessionCloseCode reports whether code may travel in SESSION_CLOSE: 1000 or a registry code.
func sessionCloseCode(code websocket.StatusCode) bool {
	if code == CloseNormal {
		return true
	}
	_, ok := CloseNames[int(code)]
	return ok
}

// engineCloseCodes are the codes an engine may put in SESSION_CLOSE: 1000 and
// every registry code whose "sentBy" names the engine. The Vault-only codes
// (AUTH_FAILED, REPLACED, LINK_UNKNOWN, ENGINE_OFFLINE) and the page-only
// HANDSHAKE_FAILED are not the engine's to send.
var engineCloseCodes = map[int]bool{
	int(CloseNormal):             true,
	int(CloseProtocol):           true,
	int(CloseUnsupportedVersion): true,
	int(CloseLinkRefused):        true,
	int(CloseFrameInvalid):       true,
	int(CloseTooLarge):           true,
	int(CloseRateLimited):        true,
	int(CloseSessionLimit):       true,
	int(CloseTimeout):            true,
	int(CloseEngineRevoked):      true,
	int(CloseEngineShutdown):     true,
}

// Control message types.
const (
	TypeChallenge      = "CHALLENGE"
	TypeAuth           = "AUTH"
	TypeReady          = "READY"
	TypeRegisterLink   = "REGISTER_LINK"
	TypeUnregisterLink = "UNREGISTER_LINK"
	TypeOK             = "OK"
	TypeError          = "ERROR"
	TypeSessionOpen    = "SESSION_OPEN"
	TypeSessionClose   = "SESSION_CLOSE"
)

// ERROR codes.
const (
	ErrLinkConflict   = "LINK_CONFLICT"
	ErrLinkLimit      = "LINK_LIMIT"
	ErrInvalidExpiry  = "INVALID_EXPIRY"
	ErrUnknownSession = "UNKNOWN_SESSION"
	ErrRateLimited    = "RATE_LIMITED"
	ErrProtocol       = "PROTOCOL"
)

// Challenge is CHALLENGE, Vault to engine.
type Challenge struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// Auth is AUTH, engine to Vault.
type Auth struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	Sig     string `json:"sig"`
}

// Ready is READY, Vault to engine.
type Ready struct {
	Type string `json:"type"`
}

// RegisterLink is REGISTER_LINK, engine to Vault.
type RegisterLink struct {
	Type      string `json:"type"`
	Ref       int64  `json:"ref"`
	LinkToken string `json:"linkToken"`
	ExpiresAt string `json:"expiresAt"`
}

// UnregisterLink is UNREGISTER_LINK, engine to Vault.
type UnregisterLink struct {
	Type      string `json:"type"`
	Ref       int64  `json:"ref"`
	LinkToken string `json:"linkToken"`
}

// OK is OK, Vault to engine.
type OK struct {
	Type string `json:"type"`
	Ref  int64  `json:"ref"`
}

// Error is ERROR, Vault to engine. Ref is 0 (omitted) when it answers no request.
type Error struct {
	Type string `json:"type"`
	Ref  int64  `json:"ref,omitempty"`
	Code string `json:"code"`
}

// SessionOpen is SESSION_OPEN, Vault to engine.
type SessionOpen struct {
	Type      string `json:"type"`
	SID       string `json:"sid"`
	LinkToken string `json:"linkToken"`
}

// SessionClose is SESSION_CLOSE, either way.
type SessionClose struct {
	Type string `json:"type"`
	SID  string `json:"sid"`
	Code int    `json:"code"`
}

// SID is a session id, 16 bytes the Vault picks per page socket.
type SID [SIDLen]byte

// String is the sid as base64url, as it travels in JSON.
func (s SID) String() string { return b64(s[:]) }

// ParseSID decodes a base64url sid.
func ParseSID(s string) (SID, error) {
	var sid SID
	b, err := decodeFixed(s, SIDLen)
	if err != nil {
		return sid, fmt.Errorf("sid: %w", err)
	}
	copy(sid[:], b)
	return sid, nil
}

// Route builds a ROUTE message: version, type, sid, payload.
func Route(sid SID, payload []byte) []byte {
	out := make([]byte, 0, routeHeaderLen+len(payload))
	out = append(out, Version, TypeRoute)
	out = append(out, sid[:]...)
	return append(out, payload...)
}

var (
	errUnsupportedVersion = errors.New("unsupported version")
	errMalformed          = errors.New("malformed")
)

// ParseRoute splits a ROUTE message. It refuses a version other than 1
// (errUnsupportedVersion) and anything else that is not a ROUTE (errMalformed).
func ParseRoute(msg []byte) (SID, []byte, error) {
	var sid SID
	if len(msg) < routeHeaderLen {
		return sid, nil, errMalformed
	}
	if msg[0] != Version {
		return sid, nil, errUnsupportedVersion
	}
	if msg[1] != TypeRoute {
		return sid, nil, errMalformed
	}
	copy(sid[:], msg[2:routeHeaderLen])
	return sid, msg[routeHeaderLen:], nil
}

// EngineID is base64url of the first 16 bytes of sha256(SPKI DER).
func EngineID(spki []byte) string {
	sum := sha256.Sum256(spki)
	return b64(sum[:EngineIDLen])
}

// ParseEngineKey decodes basalt-engine-key: a 91-byte P-256 SPKI with an
// uncompressed point, base64url without padding, in exactly that encoding.
func ParseEngineKey(s string) (*ecdsa.PublicKey, []byte, error) {
	der, err := decodeFixed(s, SPKILen)
	if err != nil {
		return nil, nil, fmt.Errorf("engine key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("engine key: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("engine key: not P-256")
	}
	again, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(again, der) {
		return nil, nil, errors.New("engine key: not canonical")
	}
	return key, der, nil
}

// AuthInput is what the engine signs to answer a CHALLENGE: the context line,
// the challenge as sent (base64url), a newline and the engine's own Vault host.
func AuthInput(challenge, host string) []byte {
	return []byte(AuthContext + challenge + "\n" + host)
}

// VerifySig checks an r || s ECDSA P-256 signature (base64url) over SHA-256 of msg.
func VerifySig(key *ecdsa.PublicKey, msg []byte, sig string) bool {
	raw, err := decodeFixed(sig, SigLen)
	if err != nil {
		return false
	}
	half := SigLen / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(key, digest[:], r, s)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeFixed decodes strict base64url without padding of exactly n bytes.
func decodeFixed(s string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("want %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// controlType reads the type of a control message.
func controlType(data []byte) (string, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return "", err
	}
	return head.Type, nil
}

func validRef(ref int64) bool { return ref >= 1 && ref <= maxRef }

func validLinkToken(s string) bool {
	_, err := decodeFixed(s, LinkTokenLen)
	return err == nil
}
