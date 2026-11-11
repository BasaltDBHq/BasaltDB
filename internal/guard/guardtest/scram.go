package guardtest

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	scramIterations = 4096
	scramSaltBytes  = 16
)

// SCRAMVerifier returns the SCRAM-SHA-256 verifier of password with salt,
// as Postgres stores it (CONTRACT.md, The setup code: verifier). Tests use
// it in place of the setup code's codec.
func SCRAMVerifier(t *testing.T, password string, salt []byte) string {
	t.Helper()
	salted, err := pbkdf2.Key(sha256.New, password, salt, scramIterations, sha256.Size)
	require.NoError(t, err)
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramIterations, enc(salt), enc(stored[:]), enc(mac(salted, "Server Key")))
}

// NewSCRAMVerifier is SCRAMVerifier with a random 16-byte salt.
func NewSCRAMVerifier(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, scramSaltBytes)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	return SCRAMVerifier(t, password, salt)
}
