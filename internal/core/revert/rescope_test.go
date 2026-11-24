package revert_test

import (
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

// The key and the challenge match values computed independently (RFC 5869
// HKDF by hand, Python hashlib), so the page and Postgres can be checked
// against the same vector.
func TestRescopeKeyAndChallenge(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 16)
	nonce := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i)
		nonce[i] = byte(100 + i)
	}
	key, err := revert.RescopeKey(secret)
	require.NoError(t, err)
	require.Equal(t, "029a6cf1bb359476e15fe9ae985592076f33d9db6103a7698e4575352a185ab8", hex.EncodeToString(key))

	sel := `{"runs": null, "scope": "TASK", "agents": null, "tables": null, "scopeId": "0193a3f0-0000-7000-8000-000000000002"}`
	got := reverttest.RescopeChallenge(uuid.MustParse("0193a3f0-0000-7000-8000-000000000001"), nonce, key, sel)
	require.Equal(t, "2612f0488e47569d425ecf45b54e4f088b80c4cdb4740901f9c2f0d437c6b0ad", hex.EncodeToString(got))

	other, err := revert.RescopeKey(append([]byte{1}, secret[1:]...))
	require.NoError(t, err)
	require.NotEqual(t, key, other)
}
