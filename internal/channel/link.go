package channel

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
)

// HKDF info strings for a link's token and psk (CONTRACT.md, Vault channel,
// Link secrets in a session).
const (
	infoLinkToken = "basalt-vault-link.1" //nolint:gosec // G101: an HKDF info label, not a credential
	infoPSK       = "basalt-vault-psk.1"
)

// LinkToken is the Vault's routing key for a link: 16 bytes, base64url on
// the wire (22 characters). It is not secret from the Vault, which sees it,
// but it is a bearer handle there: whoever holds it can register it from
// another engine and squat the link. Never log it (LogValue redacts it).
type LinkToken [LinkTokenLen]byte

// String is the token's base64url text, as in the prologue and the socket
// path: for the wire only, never for a log.
func (t LinkToken) String() string { return b64(t[:]) }

// LogValue keeps the token out of slog output, whatever the call site
// passes it as.
func (t LinkToken) LogValue() slog.Value { return slog.StringValue(redacted) }

// GoString keeps the token out of %#v, which does not call String.
func (LinkToken) GoString() string { return redacted }

// MarshalJSON keeps the token out of JSON, where slog's JSON handler puts a
// value nested in a map or struct without asking LogValue. The wire and
// the engine's files carry its String in their own string fields.
func (LinkToken) MarshalJSON() ([]byte, error) { return redactedJSON, nil }

// ParseLinkToken reads a token's 22-character base64url text.
func ParseLinkToken(s string) (LinkToken, error) {
	raw, err := unb64(s)
	if err != nil {
		return LinkToken{}, fmt.Errorf("link token: %w", err)
	}
	if len(raw) != LinkTokenLen {
		return LinkToken{}, fmt.Errorf("link token is %d bytes, want %d", len(raw), LinkTokenLen)
	}
	return LinkToken(raw), nil
}

// PSK is a link's pre-shared key. It prints as [redacted].
type PSK [PSKLen]byte

// String never shows the key.
func (PSK) String() string { return redacted }

// GoString never shows the key.
func (PSK) GoString() string { return redacted }

// LogValue keeps the key out of slog output: without it, slog's JSON
// handler marshals the array and prints every byte.
func (PSK) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON keeps the key out of JSON, nested values included.
func (PSK) MarshalJSON() ([]byte, error) { return redactedJSON, nil }

// Zero overwrites the key.
func (p *PSK) Zero() { clear(p[:]) }

// LinkKeys are what the engine keeps per short link next to sha256(secret):
// the token it registers with the Vault and the psk that keys the session.
type LinkKeys struct {
	Token LinkToken
	PSK   PSK
}

// String, GoString and LogValue never show the token or the key: %v would
// print the token's base64url through its String.
func (LinkKeys) String() string { return redacted }

// GoString never shows the token or the key.
func (LinkKeys) GoString() string { return redacted }

// LogValue keeps the token and the key out of slog output.
func (LinkKeys) LogValue() slog.Value { return slog.StringValue(redacted) }

// DeriveLink computes a link's token and psk from its secret, the 22-character
// base64url value of the link's #s= fragment: HKDF-SHA-256 with an empty salt
// and the contract's info strings. Neither output reveals the secret or the
// other output.
func DeriveLink(secret string) (LinkKeys, error) {
	s, err := unb64(secret)
	if err != nil {
		return LinkKeys{}, errors.New("link secret: not base64url")
	}
	defer clear(s)
	if len(s) != SecretLen {
		return LinkKeys{}, fmt.Errorf("link secret is %d bytes, want %d", len(s), SecretLen)
	}
	token, err := hkdf.Key(sha256.New, s, nil, infoLinkToken, LinkTokenLen)
	if err != nil {
		return LinkKeys{}, fmt.Errorf("link token: %w", err)
	}
	psk, err := hkdf.Key(sha256.New, s, nil, infoPSK, PSKLen)
	if err != nil {
		return LinkKeys{}, fmt.Errorf("link psk: %w", err)
	}
	defer clear(psk)
	return LinkKeys{Token: LinkToken(token), PSK: PSK(psk)}, nil
}
