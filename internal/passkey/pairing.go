package passkey

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// pairingDomain separates the pairing code's hash from every other hash
// over these bytes.
const pairingDomain = "basalt-pairing.1\n"

// pairingAlphabet is Crockford's base32 alphabet: no I, L, O or U.
const pairingAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// pairingLen is the pairing code's length in characters (40 bits).
const pairingLen = 8

var pairingEncoding = base32.NewEncoding(pairingAlphabet).WithPadding(base32.NoPadding)

// PairingCode is the short code the registration page shows after it hands
// a passkey back to basalt init, and that the person types into init to
// pick their own registration (CONTRACT.md, CLI): Crockford base32 of the
// first 5 bytes of sha256("basalt-pairing.1\n" || challenge ||
// credentialID || x || y), as "XXXX-XXXX". challenge is the registration
// request's, x and y the 32-byte P-256 coordinates. A key another program
// made gets another code. The vectors are api/mcp/passkey/pairing-code.json.
func PairingCode(challenge, credentialID, x, y []byte) string {
	h := sha256.New()
	h.Write([]byte(pairingDomain))
	h.Write(challenge)
	h.Write(credentialID)
	h.Write(x)
	h.Write(y)
	s := pairingEncoding.EncodeToString(h.Sum(nil)[:5])
	return s[:4] + "-" + s[4:]
}

// NormalizePairingCode reads a pairing code as a person types it: trimmed,
// any case, with or without the dash or spaces, O for 0 and I or L for 1.
// It returns the canonical 8 characters, or false when s is not 8 Crockford
// characters.
func NormalizePairingCode(s string) (string, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(s)
	if len(s) != pairingLen {
		return "", false
	}
	for _, r := range s {
		if !strings.ContainsRune(pairingAlphabet, r) {
			return "", false
		}
	}
	return s, true
}
