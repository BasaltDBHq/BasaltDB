package setup_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// A changed password reaches the agent that runs here; one for an agent
// that does not is dropped.
func TestRotationsReachTheRunningAgent(t *testing.T) {
	t.Parallel()
	r := setup.NewRotations()
	var got string
	r.Add("bot", func(pw string) { got = pw })
	r.Changed("other", "nope")
	require.Empty(t, got)
	r.Changed("bot", "s3cret")
	require.Equal(t, "s3cret", got)
}

func TestConfigGone(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	gone := setup.ConfigGone(path)
	require.True(t, gone())
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	require.False(t, gone())
}
