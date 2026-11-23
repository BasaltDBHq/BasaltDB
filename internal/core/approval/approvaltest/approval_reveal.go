package approvaltest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

const (
	revealPrefix = "basalt-reveal.1"
)

const (
	// RevealNonceLen is the length of an item's reveal nonce.
	RevealNonceLen = 16
)

// RevealChallenge is the WebAuthn challenge of a reveal proof:
// sha256(utf8("basalt-reveal.1\n" + kind + "\n" + id + "\n" +
// base64url(nonce) + "\n" + hex(sha256(revealKey)) + "\n" + rowsHash)), with
// rowsHash the binding's (a large plan's too, never its sampleHash).
func RevealChallenge(kind string, id uuid.UUID, nonce, revealKey []byte, rowsHash string) ([]byte, error) {
	if kind != approval.KindApprove && kind != approval.KindRevert {
		return nil, approval.Invalid("reveal kind %q", kind)
	}
	if len(nonce) != RevealNonceLen {
		return nil, approval.Invalid("reveal nonce is %d bytes, want %d", len(nonce), RevealNonceLen)
	}
	if len(revealKey) != approval.RevealKeyLen {
		return nil, approval.Invalid("reveal key is %d bytes, want %d", len(revealKey), approval.RevealKeyLen)
	}
	if !approval.IsHashHex(rowsHash) {
		return nil, approval.Invalid("rowsHash is not a lowercase sha256 hex digest")
	}
	keyHash := sha256.Sum256(revealKey)
	msg := strings.Join([]string{
		revealPrefix, kind, id.String(), base64.RawURLEncoding.EncodeToString(nonce),
		hex.EncodeToString(keyHash[:]), rowsHash,
	}, "\n")
	sum := sha256.Sum256([]byte(msg))
	return sum[:], nil
}
