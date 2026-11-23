package setupcode

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// SCRAM-SHA-256 parameters (RFC 5802, RFC 7677), as Postgres writes them.
const (
	// ScramIterations is the PBKDF2 iteration count, Postgres's default
	// scram_iterations and the only count a setup code accepts.
	ScramIterations = 4096
	// ScramSaltBytes is the random salt length Postgres uses.
	ScramSaltBytes = 16
	scramKeyLen    = sha256.Size
	// passwordBytes is the agent password's entropy: 256 bits.
	passwordBytes = 32
)

// verifierPattern is the schema's verifier pattern (setup-code.schema.json).
var verifierPattern = regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$`)

// NewPassword returns a random agent password: 256 bits from crypto/rand,
// hex, so it is safe in a connection string and a SQL literal.
func NewPassword() (string, error) {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random password: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewVerifier returns the SCRAM-SHA-256 verifier of password with a fresh
// random 16-byte salt: SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>.
// It is what Postgres stores in pg_authid.rolpassword. It is sensitive:
// with one observed SCRAM exchange of the role it lets its holder log in
// (CONTRACT.md, The setup code). The password is never part of an error.
func NewVerifier(password string) (string, error) {
	salt := make([]byte, ScramSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("random salt: %w", err)
	}
	return VerifierWithSalt(password, salt)
}

// VerifierWithSalt is NewVerifier with a given salt, for the golden
// fixtures. Production code uses NewVerifier.
func VerifierWithSalt(password string, salt []byte) (string, error) {
	if password == "" {
		return "", errors.New("scram verifier: empty password")
	}
	if len(salt) != ScramSaltBytes {
		return "", fmt.Errorf("scram verifier: salt is %d bytes, want %d", len(salt), ScramSaltBytes)
	}
	// Postgres runs SASLprep on the password, which leaves ASCII unchanged
	// (or fails and uses the raw bytes). Beyond ASCII it may normalise, and
	// this verifier would not match: refuse.
	for i := range len(password) {
		if password[i] >= utf8.RuneSelf {
			return "", errors.New("scram verifier: password is not ASCII")
		}
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, ScramIterations, scramKeyLen)
	if err != nil {
		return "", errors.New("scram verifier: pbkdf2 failed")
	}
	storedKey := sha256.Sum256(hmacSHA256(salted, "Client Key"))
	serverKey := hmacSHA256(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$" + strconv.Itoa(ScramIterations) + ":" + b64(salt) + "$" + b64(storedKey[:]) + ":" + b64(serverKey), nil
}

// ValidVerifier reports whether v is a SCRAM-SHA-256 verifier with 4096
// iterations, a 16-byte salt and 32-byte keys, in canonical base64.
func ValidVerifier(v string) bool {
	if !verifierPattern.MatchString(v) {
		return false
	}
	// The pattern fixes every separator's position.
	const (
		saltStart   = len("SCRAM-SHA-256$4096:")
		saltLen     = 24 // base64 of 16 bytes
		keyLen      = 44 // base64 of 32 bytes
		storedStart = saltStart + saltLen + 1
		serverStart = storedStart + keyLen + 1
	)
	parts := []struct {
		text string
		n    int
	}{
		{v[saltStart : saltStart+saltLen], ScramSaltBytes},
		{v[storedStart : storedStart+keyLen], scramKeyLen},
		{v[serverStart:], scramKeyLen},
	}
	for _, p := range parts {
		b, err := base64.StdEncoding.Strict().DecodeString(p.text)
		if err != nil || len(b) != p.n {
			return false
		}
	}
	return true
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}
