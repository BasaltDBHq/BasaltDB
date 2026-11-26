//go:build unix

package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
)

// A socket directory other agents' OS users reach is left at 0755; a
// service engine's folders are the service manager's.
func TestEnsureOwnDirsKeepsASharedSocketDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := config.Config{SocketDir: filepath.Join(base, "run"), StateDir: filepath.Join(base, "state"), Mode: config.ModeSameUser}
	require.NoError(t, os.MkdirAll(cfg.SocketDir, 0o755))
	require.NoError(t, os.Chmod(cfg.SocketDir, 0o755))
	euid := os.Geteuid()

	require.NoError(t, engine.EnsureOwnDirs(engineos.OS{}, cfg, map[string]uint32{"a": uint32(euid), "b": uint32(euid + 1)}, euid))
	fi, err := os.Stat(cfg.SocketDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "another user's agent reaches it")
	fi, err = os.Stat(cfg.StateDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	require.NoError(t, engine.EnsureOwnDirs(engineos.OS{}, cfg, map[string]uint32{"a": uint32(euid)}, euid))
	fi, err = os.Stat(cfg.SocketDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestEnsureOwnDirsSkipsAServiceEngine(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := config.Config{SocketDir: filepath.Join(base, "run"), StateDir: filepath.Join(base, "state"), Mode: config.ModeService}
	require.NoError(t, engine.EnsureOwnDirs(engineos.OS{}, cfg, map[string]uint32{"a": uint32(os.Geteuid())}, os.Geteuid()))
	_, err := os.Stat(cfg.StateDir)
	require.ErrorIs(t, err, os.ErrNotExist)
}
