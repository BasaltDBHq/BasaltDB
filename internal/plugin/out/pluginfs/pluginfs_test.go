//go:build unix

package pluginfs_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginfs"
)

func TestNoFollowRefusesASymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	files := pluginfs.Files{}
	require.Equal(t, syscall.O_NOFOLLOW|syscall.O_NONBLOCK, files.NoFollow())
	_, err := files.OpenFile(link, os.O_RDONLY|files.NoFollow(), 0)
	require.Error(t, err)
	f, err := files.OpenFile(target, os.O_RDONLY|files.NoFollow(), 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func TestOwnerAndLinksReadTheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, nil, 0o600))
	files := pluginfs.Files{}
	fi, err := files.Lstat(p)
	require.NoError(t, err)
	uid, ok := files.Owner(fi)
	require.True(t, ok)
	require.Equal(t, uint32(os.Geteuid()), uid)
	n, ok := files.Links(fi)
	require.True(t, ok)
	require.Equal(t, uint64(1), n)

	require.NoError(t, os.Link(p, filepath.Join(dir, "g")))
	fi, err = files.Lstat(p)
	require.NoError(t, err)
	n, ok = files.Links(fi)
	require.True(t, ok)
	require.Equal(t, uint64(2), n)
}

func TestWriteAtomicSetsTheModeAndLeavesNoTemporaryFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "plugins.json")
	files := pluginfs.Files{}
	require.NoError(t, files.WriteAtomic(p, []byte("[]\n"), 0o600, true))
	require.NoError(t, files.WriteAtomic(p, []byte("[1]\n"), 0o600, false))
	raw, err := files.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "[1]\n", string(raw))
	fi, err := files.Lstat(p)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	entries, err := files.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestLockTakesAndReleases(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "plugins.json.lock")
	files := pluginfs.Files{}
	release, err := files.Lock(p)
	require.NoError(t, err)
	release()
	release, err = files.Lock(p)
	require.NoError(t, err)
	release()
}
