package channel

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// HKDF info strings for a link's token and psk (CONTRACT.md, Vault channel,
// Link secrets in a session).
const (
	infoLinkToken = "basalt-vault-link.1" //nolint:gosec // G101: an HKDF info label, not a credential
	infoPSK       = "basalt-vault-psk.1"
)

// LinkToken is the Vault's routing key for a link: 16 bytes, base64url on
// the wire (22 characters). It is not secret (the Vault sees it).
type LinkToken [LinkTokenLen]byte

// String is the token's base64url text, as in the prologue and the socket path.
func (t LinkToken) String() string { return b64(t[:]) }

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

// Zero overwrites the key.
func (p *PSK) Zero() { clear(p[:]) }

// LinkKeys are what the engine keeps per short link next to sha256(secret):
// the token it registers with the Vault and the psk that keys the session.
type LinkKeys struct {
	Token LinkToken
	PSK   PSK
}

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
