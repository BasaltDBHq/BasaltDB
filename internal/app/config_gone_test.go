package app

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// With a config outside the default places, engine.json alone gone is a
// removal: its folder is not the engine's, so it may stay. A config that is
// there is not.
func TestConfigDirGoneForAConfigElsewhere(t *testing.T) {
	t.Parallel()
	for _, p := range []string{osservice.UnitPath(runtime.GOOS), osservice.RemovalJobUnit(runtime.GOOS)} {
		if _, err := os.Lstat(p); err == nil {
			t.Skip("this machine has the engine service installed")
		}
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "engine.json")
	require.True(t, configDirGone(cfg), "engine.json is gone, its folder is not the engine's")
	require.NoError(t, os.WriteFile(cfg, []byte("{}"), 0o600))
	require.False(t, configDirGone(cfg))
	require.False(t, defaultConfigPath(cfg))
}
