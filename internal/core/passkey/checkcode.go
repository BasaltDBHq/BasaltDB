package passkey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// checkCodeDomain separates the check code's hash from every other use of
// sha256 over a key.
const checkCodeDomain = "basalt-passkey-check.1\n"

// checkCodeBytes is how much of the hash the code shows: 10 bytes, five
// groups of four lowercase hex digits.
const checkCodeBytes = 10

// CheckCode is the passkey check code (CONTRACT.md, Connect, The passkey
// check code): the first 10 bytes of sha256("basalt-passkey-check.1\n" || x
// || y) for the key's 32-byte P-256 coordinates, in lowercase hex as five
// groups of four separated by a space. The connect page computes the same
// code in the browser, so a person can tell a substituted key from their own.
func CheckCode(x, y []byte) string {
	h := sha256.New()
	h.Write([]byte(checkCodeDomain))
	h.Write(x)
	h.Write(y)
	digits := hex.EncodeToString(h.Sum(nil)[:checkCodeBytes])
	var b strings.Builder
	for i := 0; i < len(digits); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(digits[i : i+4])
	}
	return b.String()
}

// CheckCode is the check code of the credential's public key.
func (c Credential) CheckCode() (string, error) {
	if c.PublicKey == nil {
		return "", errors.New("passkey has no public key")
	}
	x, y, err := c.XY()
	if err != nil {
		return "", err
	}
	return CheckCode(x, y), nil
}
