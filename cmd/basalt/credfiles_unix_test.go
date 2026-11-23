//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// As root, init --remote writes engine.json through the config directory
// it opened in paths: a config directory swapped for a symlink before the
// write (the engine's user owning a directory above it) redirects nothing.
func TestRootConfigDirWritesWhereItOpened(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir, elsewhere := filepath.Join(root, "basalt"), filepath.Join(root, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.Close()

	require.NoError(t, os.Rename(dir, dir+".moved"))
	require.NoError(t, os.Symlink(elsewhere, dir))
	_, err = d.Upsert("engine.json", config.Settings{SocketDir: "/run/basalt"}, config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore(filepath.Join(dir, "agents", "bot.url"))})
	require.NoError(t, err)
	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.FileExists(t, filepath.Join(dir+".moved", "engine.json"))

	_, err = openRootConfigDir(appSetupHost{}, dir, trusted)
	require.ErrorContains(t, err, "a symlink is refused")
}

// As root, the engine's key goes only in a state directory the config
// directory's owner owns: /usr (root's) is refused for a config directory
// this user owns, and nothing is made there.
func TestRootEngineKeyNeedsTheConfigOwnersStateDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root owns both")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "basalt")
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.Close()
	_, err = rootEngineKey(appSetupHost{}, "/usr", runtime.GOOS, d, time.Now)
	require.ErrorContains(t, err, fmt.Sprintf("the state directory /usr is owned by uid 0, not uid %d (the owner of the config directory %s)", os.Geteuid(), dir))
	require.NoFileExists(t, filepath.Join("/usr", channel.KeyFileName))

	// Its own state directory: the key is made there.
	state := filepath.Join(dir, "state")
	require.NoError(t, os.Mkdir(state, 0o700))
	spki, err := rootEngineKey(appSetupHost{}, state, runtime.GOOS, d, time.Now)
	require.NoError(t, err)
	require.NotEmpty(t, spki)
}

// A missing state directory: the service manager makes only the default
// one; one next to a --config is made by hand.
func TestMissingStateDirHint(t *testing.T) {
	t.Parallel()
	def := config.DefaultStateDir(runtime.GOOS)
	require.ErrorContains(t, missingStateDir(def, runtime.GOOS, 998), "start the engine's service once")
	err := missingStateDir("/srv/bot/state", runtime.GOOS, 998)
	require.ErrorContains(t, err, "sudo install -d -m 0700 -o 998 /srv/bot/state")
	require.NotContains(t, err.Error(), "service once")
}

// As root, engine.json is written through the config directory opened, not
// by path: the directory swapped for a symlink before the write redirects
// nothing.
func TestRootConfigDirUpsertStaysInTheOpenedDir(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir, elsewhere := filepath.Join(root, "basalt"), filepath.Join(root, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	trusted, err := rootTrustedOwner(dir)
	require.NoError(t, err)
	d, err := openRootConfigDir(appSetupHost{}, dir, trusted)
	require.NoError(t, err)
	defer d.Close()
	require.NoError(t, os.Rename(dir, dir+".moved"))
	require.NoError(t, os.Symlink(elsewhere, dir))
	_, err = d.Upsert("engine.json", config.Settings{SocketDir: "/run/basalt"}, config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore(filepath.Join(dir, "agents", "bot.url"))})
	require.NoError(t, err)
	requireEmptyDir(t, elsewhere)
	c, err := config.Load(filepath.Join(dir+".moved", "engine.json"))
	require.NoError(t, err)
	require.Equal(t, "bot", c.Agents[0].Name)
}
