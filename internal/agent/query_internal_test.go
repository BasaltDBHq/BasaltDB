package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTruncateKeepsRunes(t *testing.T) {
	t.Parallel()
	require.Equal(t, "abc", truncate("abc", 5))
	require.Equal(t, "ab", truncate("abé", 3), "never cut inside a rune")
	require.Equal(t, "abé", truncate("abé", 4))
}
