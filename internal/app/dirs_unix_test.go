//go:build unix

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

func TestEnsurePrivateDirsRecreates(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "a", "run")

	require.NoError(t, ensurePrivateDirs(os.Geteuid(), d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestEnsurePrivateDirsTightens(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.Mkdir(d, 0o755))
	require.NoError(t, os.Chmod(d, 0o755))
	inside := filepath.Join(d, "pii.key")
	require.NoError(t, os.WriteFile(inside, []byte("k"), 0o600))

	require.NoError(t, ensurePrivateDirs(os.Geteuid(), d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	fi, err = os.Stat(inside)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "what is inside is not touched")
}

// A folder another user owns is not ours to change.
func TestEnsurePrivateDirsLeavesOthers(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(d, 0o755))
	require.NoError(t, os.Chmod(d, 0o755))

	require.NoError(t, ensurePrivateDirs(os.Geteuid()+1, d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
}

func TestEnsurePrivateDirsRefusesSymlink(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.Chmod(target, 0o755))
	link := filepath.Join(base, "run")
	require.NoError(t, os.Symlink(target, link))

	err := ensurePrivateDirs(os.Geteuid(), link)

	require.ErrorContains(t, err, "not a plain directory")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "what it points at is not changed")
}

// A socket directory other agents' OS users reach is left at 0755; a
// service engine's folders are the service manager's.
func TestEnsureOwnDirsKeepsASharedSocketDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := config.Config{SocketDir: filepath.Join(base, "run"), StateDir: filepath.Join(base, "state"), Mode: config.ModeSameUser}
	require.NoError(t, os.MkdirAll(cfg.SocketDir, 0o755))
	require.NoError(t, os.Chmod(cfg.SocketDir, 0o755))
	euid := os.Geteuid()

	require.NoError(t, ensureOwnDirs(cfg, map[string]uint32{"a": uint32(euid), "b": uint32(euid + 1)}, euid))
	fi, err := os.Stat(cfg.SocketDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "another user's agent reaches it")
	fi, err = os.Stat(cfg.StateDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	require.NoError(t, ensureOwnDirs(cfg, map[string]uint32{"a": uint32(euid)}, euid))
	fi, err = os.Stat(cfg.SocketDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestEnsureOwnDirsSkipsAServiceEngine(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := config.Config{SocketDir: filepath.Join(base, "run"), StateDir: filepath.Join(base, "state"), Mode: config.ModeService}
	require.NoError(t, ensureOwnDirs(cfg, map[string]uint32{"a": uint32(os.Geteuid())}, os.Geteuid()))
	_, err := os.Stat(cfg.StateDir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// A dangling symlink is named for what it is, not as a failed mkdir.
func TestEnsurePrivateDirsRefusesADanglingSymlink(t *testing.T) {
	t.Parallel()
	link := filepath.Join(t.TempDir(), "run")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "nowhere"), link))
	require.ErrorContains(t, ensurePrivateDirs(os.Geteuid(), link), "not a plain directory")
}
