// Package channel is the engine's side of the Vault channel (CONTRACT.md,
// Vault channel): the engine's keys and their file, the link-session
// handshake (Noise_NNpsk0_P256_AESGCM_SHA256 with an engine signature) and the
// session frames that follow it.
//
// Everything here uses Go's standard library only (crypto/ecdh, crypto/ecdsa,
// crypto/hkdf, crypto/hmac, crypto/aes, crypto/cipher). No value of this
// package prints key material: keys, psks and session keys format as
// "[redacted]", and errors name paths and reasons, never bytes.
//
// The shared vectors in api/mcp/vault/testdata pin every byte this package
// writes and every refusal it makes.
package channel

import (
	"encoding/base64"
	"fmt"
)

// Wire constants of CONTRACT.md, Vault channel.
const (
	// wireVersion is the only version byte.
	wireVersion byte = 0x01
	// typeHello is handshake message 1, page to engine.
	typeHello byte = 0x01
	// typeWelcome is handshake message 2, engine to page.
	typeWelcome byte = 0x02
	// typeFrame is a session frame, either way.
	typeFrame byte = 0x03
	// headerLen is the version and type bytes in front of every message.
	headerLen = 2

	// PointLen is an uncompressed SEC1 P-256 point: 0x04 || X || Y.
	PointLen = 65
	// tagLen is the AES-GCM tag.
	tagLen = 16
	// LinkTokenLen is a decoded linkToken.
	LinkTokenLen = 16
	// PSKLen is a link's pre-shared key.
	PSKLen = 32
	// SecretLen is a decoded link secret (CONTRACT.md, Link secrets).
	SecretLen = 16
	// Message1Len is the exact size of handshake message 1.
	Message1Len = headerLen + LinkTokenLen + PointLen + tagLen // 99
	// Message2Max is the largest handshake message 2.
	Message2Max = 1024

	// lenPrefix is the big-endian content length in front of padded plaintext.
	lenPrefix = 4
	// padMin is the smallest padded plaintext, 1 KiB.
	padMin = 1024
	// padMax is the largest padded plaintext, 32 KiB.
	padMax = 32768
	// ContentMax is the most content one frame carries.
	ContentMax = padMax - lenPrefix
	// FrameMax is the largest frame on the wire: header, padded plaintext, tag.
	FrameMax = headerLen + padMax + tagLen // 32 786

	// SigLen is an ECDSA P-256 signature as r || s (IEEE P1363).
	SigLen = 64
	// hashLen is SHA-256's output, Noise's HASHLEN.
	hashLen = 32
)

// CloseError is a refusal carrying a WebSocket close code of the channel's
// registry (api/mcp/vault/close-codes.json): the caller closes the session
// with Code and String as the reason.
type CloseError uint16

// Code is the WebSocket close code.
func (c CloseError) Code() uint16 { return uint16(c) }

// The registry, 4000 to 4014.
const (
	ErrProtocol           CloseError = 4000
	ErrUnsupportedVersion CloseError = 4001
	ErrAuthFailed         CloseError = 4002
	ErrReplaced           CloseError = 4003
	ErrLinkUnknown        CloseError = 4004
	ErrEngineOffline      CloseError = 4005
	ErrLinkRefused        CloseError = 4006
	ErrHandshakeFailed    CloseError = 4007
	ErrFrameInvalid       CloseError = 4008
	ErrTooLarge           CloseError = 4009
	ErrRateLimited        CloseError = 4010
	ErrSessionLimit       CloseError = 4011
	ErrTimeout            CloseError = 4012
	ErrEngineRevoked      CloseError = 4013
	ErrEngineShutdown     CloseError = 4014
)

var closeNames = map[CloseError]string{
	ErrProtocol:           "PROTOCOL",
	ErrUnsupportedVersion: "UNSUPPORTED_VERSION",
	ErrAuthFailed:         "AUTH_FAILED",
	ErrReplaced:           "REPLACED",
	ErrLinkUnknown:        "LINK_UNKNOWN",
	ErrEngineOffline:      "ENGINE_OFFLINE",
	ErrLinkRefused:        "LINK_REFUSED",
	ErrHandshakeFailed:    "HANDSHAKE_FAILED",
	ErrFrameInvalid:       "FRAME_INVALID",
	ErrTooLarge:           "TOO_LARGE",
	ErrRateLimited:        "RATE_LIMITED",
	ErrSessionLimit:       "SESSION_LIMIT",
	ErrTimeout:            "TIMEOUT",
	ErrEngineRevoked:      "ENGINE_REVOKED",
	ErrEngineShutdown:     "ENGINE_SHUTDOWN",
}

// String is the code's registry name, the close reason.
func (c CloseError) String() string {
	if name, ok := closeNames[c]; ok {
		return name
	}
	return fmt.Sprintf("CLOSE_%d", uint16(c))
}

// Error makes a CloseError a refusal.
func (c CloseError) Error() string { return "vault channel: " + c.String() }

// Transport is the socket a session runs over; it is part of the prologue.
type Transport string

// The transports (CONTRACT.md, Vault channel; DIRECT is M4.1's).
const (
	TransportRelay  Transport = "RELAY"
	TransportDirect Transport = "DIRECT"
)

func (t Transport) valid() bool { return t == TransportRelay || t == TransportDirect }

// redacted is what every secret-holding value prints as.
const redacted = "[redacted]"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes base64url without padding and refuses a non-canonical form.
func unb64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
