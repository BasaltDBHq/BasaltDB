//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

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
