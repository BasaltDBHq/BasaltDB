//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// The engine's user owns agents/, so it could plant a symlink to a root-only
// file; the install, running as root, must not copy what it points to.
func TestKeptCredentialSpecRefusesASymlink(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	spec := servicespec.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
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

// TestMain moves temp directories out of a sticky, world-writable /tmp
// (Linux): the install refuses to read the engine's files below one, as it
// should, and tests stand in for the engine user in their own directories.
func TestMain(m *testing.M) {
	// With this set, the test binary is the basalt binary: a supervisor
	// test runs it as basalt engine --supervise, which runs it again as
	// basalt engine.
	if os.Getenv(testAsBasaltEnv) != "" {
		main()
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
