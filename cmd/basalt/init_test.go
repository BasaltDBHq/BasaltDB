package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

func TestResolveExecutableFollowsLinks(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	target := filepath.Join(dir, "basalt-real")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o700))
	link := filepath.Join(dir, "basalt")
	require.NoError(t, os.Symlink(target, link))
	require.Equal(t, target, cli.ResolveExecutable(link))
	require.Equal(t, filepath.Join(dir, "gone"), cli.ResolveExecutable(filepath.Join(dir, "gone")))
}

// Saved init arguments never carry a password or a connection string with
// user info: init and service install refuse them before engine.json is
// written.
func TestRefuseSecretInitArgs(t *testing.T) {
	t.Parallel()
	require.NoError(t, refuseSecretInitArgs([]string{"--agent=bot", "--write=public.leads", "--passkey-origin=https://portal.basaltvault.app"}))
	for _, bad := range [][]string{
		{"--database-url=postgres://admin:" + "pw@db/app"}, // split so no literal credential sits in the source
		{"--x", "postgres://admin@db/app"},
		{"--y=host=db password=pw"},
		{"--Z=PASSWORD=pw"},
	} {
		require.Error(t, refuseSecretInitArgs(bad), "%v", bad)
	}
}
