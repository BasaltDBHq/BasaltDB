package revert_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// The engine's revert request carries revealNonce only when it has one.
func TestRequestRevealNonce(t *testing.T) {
	t.Parallel()
	r := revert.Request{Binding: "{}", Lines: []string{}}
	out, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(out), "revealNonce")
	r.RevealNonce = make([]byte, 16)
	out, err = json.Marshal(r)
	require.NoError(t, err)
	require.Contains(t, string(out), `"revealNonce":"AAAAAAAAAAAAAAAAAAAAAA"`)
}
