package revert

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// The widen proof (CONTRACT.md, Revert, Rescope, widen and reject).
const (
	rescopePrefix  = "basalt-rescope.1"
	rescopeKeyInfo = "basalt-rescope-key.1"
	// RescopeKeyLen is the length of the key derived from a new link
	// secret; Postgres refuses any other.
	RescopeKeyLen = 32
)

// RescopeKey derives the key the engine passes Postgres for a widen from
// the page's new link secret: HKDF-SHA-256 with an empty salt and info
// "basalt-rescope-key.1". The secret itself never reaches Postgres.
func RescopeKey(newSecret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, newSecret, nil, rescopeKeyInfo, RescopeKeyLen)
}

// RescopeChallenge is the WebAuthn challenge of a widen proof:
// sha256(utf8("basalt-rescope.1\n" + revertId + "\n" + base64url(nonce) +
// "\n" + hex(sha256(rescopeKey)) + "\n" + selectText)), where selectText is
// the descriptor exactly as Postgres normalizes it.
func RescopeChallenge(revertID uuid.UUID, nonce, rescopeKey []byte, selectText string) []byte {
	keyHash := sha256.Sum256(rescopeKey)
	msg := strings.Join([]string{
		rescopePrefix, revertID.String(), base64.RawURLEncoding.EncodeToString(nonce),
		hex.EncodeToString(keyHash[:]), selectText,
	}, "\n")
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}
