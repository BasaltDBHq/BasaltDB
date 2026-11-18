//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// The engine's user owns agents/, so it could plant a symlink to a root-only
// file; the install, running as root, must not copy what it points to.
func TestKeptCredentialSpecRefusesASymlink(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	spec := service.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
	a := agentInstall{name: "bot", osUser: "tester", keepCredential: true}
	cred := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	target := filepath.Join(t.TempDir(), "id_rsa")
	require.NoError(t, os.WriteFile(target, []byte("PRIVATE KEY\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(cred), 0o700))
	require.NoError(t, os.Symlink(target, cred))

	got, err := keptCredentialSpec(spec, a, false)
	require.Error(t, err)
	for _, f := range got.Files {
		require.NotContains(t, string(f.Content), "PRIVATE KEY", "nothing is copied")
	}
}

func TestReadKeptCredentialRefusesAHardlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "root-only")
	require.NoError(t, os.WriteFile(secret, []byte("PRIVATE KEY\n"), 0o600))
	path := filepath.Join(dir, "bot.url")
	require.NoError(t, os.Link(secret, path))

	got, err := readKeptCredential(path, me(t))

	require.ErrorContains(t, err, "hard link")
	require.Empty(t, got)
}

func TestReadKeptCredentialRefusesADirectory(t *testing.T) {
	t.Parallel()
	_, err := readKeptCredential(t.TempDir(), me(t))
	require.Error(t, err)
}

func TestReadKeptCredentialChecksTheOpenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bot.url")
	require.NoError(t, os.WriteFile(path, []byte("postgres://r:p@h/d\n"), 0o600))
	got, err := readKeptCredential(path, me(t))
	require.NoError(t, err)
	require.Equal(t, "postgres://r:p@h/d", got)

	require.NoError(t, os.Chmod(path, 0o644))
	_, err = readKeptCredential(path, me(t))
	require.Error(t, err, "a file others can read is refused")
	require.NoError(t, os.Chmod(path, 0o600))
	_, err = readKeptCredential(path, "nobody-such-user")
	require.Error(t, err, "a file owned by someone else is refused")
}

// fifoWait bounds how long a FIFO test waits before it calls the open hung.
const fifoWait = 5 * time.Second

// withinFIFOWait runs fn and fails the test if it does not return in time.
func withinFIFOWait(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(fifoWait):
		t.Fatal("opening a FIFO blocked")
		return nil
	}
}

// The engine's user could plant a FIFO where root reads or locks a file:
// every open returns an error at once instead of waiting for a writer.
func TestCredentialOpensRefuseAFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bot.url")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	err := withinFIFOWait(t, func() error {
		_, err := readKeptCredential(path, me(t))
		return err
	})
	require.ErrorContains(t, err, "not a regular file")

	err = withinFIFOWait(t, func() error {
		_, _, err := readOwnCredential(path)
		return err
	})
	require.ErrorContains(t, err, "not a regular file")

	err = withinFIFOWait(t, func() error {
		unlock, err := lockFile(path)
		if err == nil {
			unlock()
		}
		return err
	})
	require.ErrorContains(t, err, "not a regular file")
}

// TestMain moves temp directories out of a sticky, world-writable /tmp
// (Linux): the install refuses to read the engine's files below one, as it
// should, and tests stand in for the engine user in their own directories.
func TestMain(m *testing.M) {
	// The test binary doubles as the test plugin of basalt plugin check.
	if len(os.Args) > 1 && os.Args[1] == testPluginFlag {
		testPluginMain(os.Args[2:])
	}
	if fi, err := os.Stat(os.TempDir()); err == nil && fi.Mode()&os.ModeSticky != 0 {
		dir, err := os.MkdirTemp(".", ".tmp-test-")
		if err != nil {
			panic(err)
		}
		abs, _ := filepath.Abs(dir)
		os.Setenv("TMPDIR", abs)
		code := m.Run()
		_ = os.RemoveAll(abs)
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// The engine user owns the config directory, so it could swap agents/ for
// a symlink to a directory holding someone else's file: the read refuses it.
func TestReadKeptCredentialRefusesASymlinkedDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "bot.url"), []byte("PRIVATE KEY\n"), 0o600))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "agents")))

	got, err := readKeptCredential(filepath.Join(dir, "agents", "bot.url"), me(t))

	require.ErrorContains(t, err, "a symlink is refused")
	require.Empty(t, got)
}

// A root-owned file with one link, as a hardlink to an old root-only file
// looks once its other name is gone, is not the engine user's: refused.
func TestReadKeptCredentialRefusesARootOwnedFile(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("as root the engine user would be root")
	}
	path, err := filepath.EvalSymlinks("/etc/hosts")
	require.NoError(t, err)

	got, err := readKeptCredential(path, me(t))

	require.ErrorContains(t, err, "owned by uid 0, not "+me(t))
	require.Empty(t, got)
}
