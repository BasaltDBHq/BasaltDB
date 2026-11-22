package mcpcontract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestToolsNameNoRemovedTransport fails if a served tool schema mentions the
// removed direct transport or a tunnel, so the text cannot come back.
func TestToolsNameNoRemovedTransport(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("tools/*")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		text := strings.ToLower(string(raw))
		require.NotContains(t, text, "tunnel", f)
		require.NotContains(t, text, "direct transport", f)
	}
}
