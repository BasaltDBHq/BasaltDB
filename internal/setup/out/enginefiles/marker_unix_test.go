//go:build unix

package enginefiles_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup/out/enginefiles"
)

// The removal job's marker is created in place, empty and the engine's
// alone, and never through a symlink at its path.
func TestCreateMarker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	marker := filepath.Join(dir, "remove-requested")
	require.NoError(t, enginefiles.Files{}.CreateMarker(marker))
	fi, err := os.Lstat(marker)
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular())
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	require.Zero(t, fi.Size())
	require.NoError(t, enginefiles.Files{}.CreateMarker(marker), "again: still one empty file")

	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	require.Error(t, enginefiles.Files{}.CreateMarker(link))
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.Error(t, enginefiles.Files{}.CreateMarker(fifo), "a FIFO is refused, without blocking")
	b, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "keep", string(b), "the link's target is untouched")
}
