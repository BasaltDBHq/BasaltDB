//go:build unix

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// realDir is a temporary directory with no symlink on its path.
func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

// openDir opens dir as root would (service.OpenTrustedDir), trusting this
// process's user.
func openDir(t *testing.T, dir string) *service.TrustedDir {
	t.Helper()
	d, err := service.OpenTrustedDir(dir, os.Geteuid(), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func trustedCheck(f *os.File) error { return config.CheckTrustedConfig(f, os.Geteuid()) }

// The config is locked, read and written relative to the directory opened
// first: a config directory swapped for a symlink between the read and the
// write (by a user owning a directory above it) redirects nothing.
func TestUpsertAgentVaultAtStaysInTheOpenedDirectory(t *testing.T) {
	t.Parallel()
	root := realDir(t)
	cfgDir, elsewhere := filepath.Join(root, "basalt"), filepath.Join(root, "elsewhere")
	require.NoError(t, os.Mkdir(cfgDir, 0o700))
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	cfg := filepath.Join(cfgDir, "engine.json")
	require.NoError(t, config.UpsertAgent(cfg, config.Settings{SocketDir: "/run/basalt"}, config.Agent{Name: "one", OSUser: "bot", CredentialFile: "/c/one.url"}))
	d := openDir(t, cfgDir)

	// The swap: the config directory moves away and a symlink takes its
	// place.
	moved := filepath.Join(root, "moved")
	require.NoError(t, os.Rename(cfgDir, moved))
	require.NoError(t, os.Symlink(elsewhere, cfgDir))

	_, err := config.UpsertAgentVaultAt(d, "engine.json", trustedCheck, -1, config.Settings{}, config.Agent{Name: "two", OSUser: "bot", CredentialFile: "/c/two.url"})
	require.NoError(t, err)
	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing reaches the symlink's target")
	c, err := config.Load(filepath.Join(moved, "engine.json"))
	require.NoError(t, err)
	require.Len(t, c.Agents, 2, "the write went to the directory opened, merged with what it read there")

	// Opening the swapped path again is refused.
	_, err = service.OpenTrustedDir(cfgDir, os.Geteuid(), false)
	require.ErrorContains(t, err, "a symlink is refused")

	cleared, err := config.ClearSetupAt(d, "engine.json", trustedCheck, -1, "two", "none")
	require.NoError(t, err)
	require.False(t, cleared)
}

// The config read through the directory is checked first: a symlink, a
// hard link or a file the check refuses is never read or replaced.
func TestUpsertAgentVaultAtRefusesAnUntrustedConfig(t *testing.T) {
	t.Parallel()
	dir := realDir(t)
	d := openDir(t, dir)
	cfg := filepath.Join(dir, "engine.json")
	require.NoError(t, config.UpsertAgent(cfg, config.Settings{SocketDir: "/run/basalt"}, config.Agent{Name: "one", OSUser: "bot", CredentialFile: "/c/one.url"}))
	before, err := os.ReadFile(cfg)
	require.NoError(t, err)

	require.NoError(t, os.Chmod(cfg, 0o620))
	_, err = config.UpsertAgentVaultAt(d, "engine.json", trustedCheck, -1, config.Settings{}, config.Agent{Name: "two", OSUser: "bot", CredentialFile: "/c/two.url"})
	require.ErrorContains(t, err, "writable by group or others")
	require.NoError(t, os.Chmod(cfg, 0o600))

	require.NoError(t, os.Link(cfg, filepath.Join(dir, "hard")))
	_, err = config.UpsertAgentVaultAt(d, "engine.json", trustedCheck, -1, config.Settings{}, config.Agent{Name: "two", OSUser: "bot", CredentialFile: "/c/two.url"})
	require.ErrorContains(t, err, "more than one hard link")
	require.NoError(t, os.Remove(filepath.Join(dir, "hard")))

	after, err := os.ReadFile(cfg)
	require.NoError(t, err)
	require.Equal(t, before, after)

	other := filepath.Join(realDir(t), "engine.json")
	require.NoError(t, os.Rename(cfg, other))
	require.NoError(t, os.Symlink(other, cfg))
	_, err = config.ClearSetupAt(d, "engine.json", trustedCheck, -1, "one", "x")
	require.ErrorContains(t, err, "is a symlink, which is refused")
}

// LockAt locks a file relative to the directory: a second holder gets
// ErrLocked, and a symlink or a hard link at the name is a
// *LockUnusableError.
func TestLockAt(t *testing.T) {
	t.Parallel()
	dir := realDir(t)
	d := openDir(t, dir)
	unlock, err := config.LockAt(d, "bot.url.lock")
	require.NoError(t, err)
	_, err = config.LockAt(d, "bot.url.lock")
	require.ErrorIs(t, err, config.ErrLocked)
	unlock()
	unlock, err = config.LockAt(d, "bot.url.lock")
	require.NoError(t, err)
	unlock()

	var unusable *config.LockUnusableError
	require.NoError(t, os.Symlink(filepath.Join(dir, "bot.url.lock"), filepath.Join(dir, "link.lock")))
	_, err = config.LockAt(d, "link.lock")
	require.ErrorAs(t, err, &unusable)
	require.ErrorContains(t, err, "is a symlink, which is refused")

	require.NoError(t, os.Link(filepath.Join(dir, "bot.url.lock"), filepath.Join(dir, "hard.lock")))
	_, err = config.LockAt(d, "hard.lock")
	require.ErrorAs(t, err, &unusable)
}

// LockOpenFile, unprivileged: a lock file with a second hard link is a
// *LockUnusableError (and the file is closed), and a second lock on the
// same file is ErrLocked.
func TestLockOpenFile(t *testing.T) {
	t.Parallel()
	dir := realDir(t)
	path := filepath.Join(dir, "a.lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, config.FileMode)
		require.NoError(t, err)
		return f
	}
	unlock, err := config.LockOpenFile(open(), os.Geteuid())
	require.NoError(t, err)
	_, err = config.LockOpenFile(open(), os.Geteuid())
	require.ErrorIs(t, err, config.ErrLocked)
	unlock()

	require.NoError(t, os.Link(path, filepath.Join(dir, "b.lock")))
	f := open()
	_, err = config.LockOpenFile(f, os.Geteuid())
	var unusable *config.LockUnusableError
	require.ErrorAs(t, err, &unusable)
	require.Error(t, f.Close(), "the file was closed on the error")
}

// ReadCredentialAt reads a 0600 credential owned by this process's user or
// the directory's owner, and refuses a wider mode, a symlink or a missing
// file (fs.ErrNotExist); SameFileAt tells a replaced file.
func TestReadCredentialAt(t *testing.T) {
	t.Parallel()
	dir := realDir(t)
	d := openDir(t, dir)
	require.NoError(t, d.WriteFile("bot.url", []byte("postgres://a:b@h/db\n"), 0o600, -1))
	dsn, fi, err := config.ReadCredentialAt(d, "bot.url")
	require.NoError(t, err)
	require.Equal(t, "postgres://a:b@h/db", dsn)
	require.NoError(t, config.SameFileAt(d, "bot.url", fi))
	require.NoError(t, d.WriteFile("bot.url", []byte("postgres://a:c@h/db\n"), 0o600, -1))
	require.ErrorContains(t, config.SameFileAt(d, "bot.url", fi), "changed since it was read")

	_, _, err = config.ReadCredentialAt(d, "missing.url")
	require.True(t, errors.Is(err, os.ErrNotExist), err)

	require.NoError(t, os.Chmod(filepath.Join(dir, "bot.url"), 0o640))
	_, _, err = config.ReadCredentialAt(d, "bot.url")
	require.ErrorContains(t, err, "readable by the engine's user only")

	require.NoError(t, os.Symlink(filepath.Join(dir, "bot.url"), filepath.Join(dir, "link.url")))
	_, _, err = config.ReadCredentialAt(d, "link.url")
	require.ErrorContains(t, err, "is a symlink, which is refused")
}

// As real root only: the config UpsertAgentVaultAt and ClearSetupAt write
// is given to the owner they are passed (the config directory's), before
// it appears under its name.
func TestUpsertAgentVaultAtGivesTheConfigToItsOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const nobody = 65534
	dir := realDir(t)
	require.NoError(t, os.Chown(dir, nobody, -1))
	d, err := service.OpenTrustedDir(dir, nobody, false)
	require.NoError(t, err)
	defer d.Close()
	check := func(f *os.File) error { return config.CheckTrustedConfig(f, nobody) }
	_, err = config.UpsertAgentVaultAt(d, "engine.json", check, nobody, config.Settings{SocketDir: "/run/basalt"},
		config.Agent{Name: "one", OSUser: "bot", CredentialFile: "/c/one.url"})
	require.NoError(t, err)
	fi, err := os.Stat(filepath.Join(dir, "engine.json"))
	require.NoError(t, err)
	require.Equal(t, uint32(nobody), fi.Sys().(*syscall.Stat_t).Uid)
	_, err = config.ClearSetupAt(d, "engine.json", check, nobody, "one", "x")
	require.NoError(t, err)
}
