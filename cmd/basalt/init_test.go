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
