package reverttest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// RescopeChallenge is the WebAuthn challenge of a widen proof:
// sha256(utf8("basalt-rescope.1\n" + revertId + "\n" + base64url(nonce) +
// "\n" + hex(sha256(rescopeKey)) + "\n" + selectText)), where selectText is
// the descriptor exactly as Postgres normalizes it.
func RescopeChallenge(revertID uuid.UUID, nonce, rescopeKey []byte, selectText string) []byte {
	keyHash := sha256.Sum256(rescopeKey)
	msg := strings.Join([]string{
		revert.RescopePrefix, revertID.String(), base64.RawURLEncoding.EncodeToString(nonce),
		hex.EncodeToString(keyHash[:]), selectText,
	}, "\n")
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}
