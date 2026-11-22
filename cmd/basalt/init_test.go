package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// basalt mcp finds the config and the socket directory itself, so the line
// is the same wherever the config is.
func TestMCPArgsNameOnlyTheAgent(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot"}, mcpArgs("bot", "basalt"))
	require.Equal(t, []string{fakeBin, "mcp", "--agent", "bot"}, mcpArgs("bot", mcpBinary(newFakeHost(t))))
}

func TestResolveExecutableFollowsLinks(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	target := filepath.Join(dir, "basalt-real")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o700))
	link := filepath.Join(dir, "basalt")
	require.NoError(t, os.Symlink(target, link))
	require.Equal(t, target, resolveExecutable(link))
	require.Equal(t, filepath.Join(dir, "gone"), resolveExecutable(filepath.Join(dir, "gone")))
}

func TestTemporaryBinaryWarning(t *testing.T) {
	t.Parallel()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.Contains(t, temporaryBinaryWarning(filepath.Join(tmp, "x", "basalt"), tmp), "put the binary in a folder that survives")
	require.Contains(t, temporaryBinaryWarning("/home/u/.cache/go-build/ab/basalt", tmp), "/home/u/.cache/go-build/ab/basalt")
	require.Empty(t, temporaryBinaryWarning("/opt/basalt/bin/basalt", tmp))
	require.Empty(t, temporaryBinaryWarning(tmp+"x/basalt", tmp))
}

func TestTemporaryBinaryWarningResolvesLinkedTempDir(t *testing.T) {
	t.Parallel()
	realTmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	link := filepath.Join(t.TempDir(), "tmp-link")
	require.NoError(t, os.Symlink(realTmp, link))
	bin := filepath.Join(realTmp, "basalt")
	require.Contains(t, temporaryBinaryWarning(bin, link), "put the binary in a folder that survives")
	require.Empty(t, temporaryBinaryWarning("/opt/basalt/bin/basalt", link))
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
