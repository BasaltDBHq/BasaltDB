//go:build unix

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// An agent-operated engine's default tree goes whole; the binary and
// anything outside it stay, except the agent's credential file there when
// it is a plain file of this user. A symlinked credential stays and is
// reported.
func TestRemoveEngineFiles(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, config.UserDirName)
	for _, d := range []string{"agents", "run", "state", "trust.d"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, d), 0o700))
	}
	configPath := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "state", "engine.log"), []byte("x"), 0o600))
	outside := filepath.Join(base, "elsewhere")
	require.NoError(t, os.MkdirAll(outside, 0o700))
	cred := filepath.Join(outside, "bot.url")
	require.NoError(t, os.WriteFile(cred, []byte("postgres://x"), 0o600))
	keep := filepath.Join(outside, "basalt")
	require.NoError(t, os.WriteFile(keep, []byte("binary"), 0o700))
	cfg := config.Config{
		SocketDir: filepath.Join(dir, "run"), StateDir: filepath.Join(dir, "state"),
		Agents: []config.Agent{{Name: "bot", Store: config.PostgresStore(cred)}},
	}

	require.NoError(t, removeEngineFiles(cfg, configPath, "bot"))
	_, err := os.Lstat(dir)
	require.ErrorIs(t, err, os.ErrNotExist, "the config folder is gone")
	_, err = os.Lstat(cred)
	require.ErrorIs(t, err, os.ErrNotExist, "the credential outside it is gone")
	_, err = os.Lstat(keep)
	require.NoError(t, err, "the binary stays")

	t.Run("a symlinked credential outside stays", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, config.UserDirName)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		configPath := filepath.Join(dir, "engine.json")
		require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))
		target := filepath.Join(base, "precious")
		require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
		link := filepath.Join(base, "bot.url")
		require.NoError(t, os.Symlink(target, link))
		cfg := config.Config{Agents: []config.Agent{{Name: "bot", Store: config.PostgresStore(link)}}}
		err := removeEngineFiles(cfg, configPath, "bot")
		require.ErrorIs(t, err, errCredentialKept)
		require.Equal(t, "CREDENTIAL_FILE_KEPT", keptReason(err))
		_, err = os.Stat(target)
		require.NoError(t, err, "a link's target is never touched")
	})

	t.Run("a config elsewhere: only engine.json goes", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "engine.json")
		require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))
		other := filepath.Join(dir, "notes.txt")
		require.NoError(t, os.WriteFile(other, []byte("mine"), 0o600))
		require.NoError(t, removeEngineFiles(config.Config{}, configPath, "bot"))
		_, err := os.Lstat(configPath)
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Lstat(other)
		require.NoError(t, err, "a folder that is not the engine's own stays")
	})
}
