package browser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommand(t *testing.T) {
	t.Parallel()
	for goos, want := range map[string]string{"darwin": "open", "linux": "xdg-open"} {
		got, ok := Command(goos)
		require.True(t, ok, goos)
		require.Equal(t, want, got)
	}
	_, ok := Command("windows")
	require.False(t, ok)
}
