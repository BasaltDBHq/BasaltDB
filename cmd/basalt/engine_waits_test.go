package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Only a service engine on a first install waits for its config: its own
// OS user, the system config path, whose folder exists, and no engine.json.
func TestWaitsForConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	system := filepath.Join(dir, "engine.json")
	require.True(t, waitsForConfigAt(501, system, system))

	require.False(t, waitsForConfigAt(0, system, system), "root reads its config the hardened way and never waits")
	other := filepath.Join(t.TempDir(), "engine.json")
	require.False(t, waitsForConfigAt(501, other, system), "a config path of its own: a missing file is an error")
	missingDir := filepath.Join(dir, "gone", "engine.json")
	require.False(t, waitsForConfigAt(501, missingDir, missingDir), "no folder: nothing installed this engine")

	require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
	require.False(t, waitsForConfigAt(501, system, system), "a config that exists is loaded")
	require.NoError(t, os.Remove(system))
	require.NoError(t, os.Symlink(other, system))
	require.False(t, waitsForConfigAt(501, system, system), "a dangling link is not a missing config")
}
