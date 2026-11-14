//go:build unix

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// OpenTrustedDir refuses a symlinked directory, makes a missing one (and
// its missing parents) 0700, and keeps working on the directory it opened
// when the path is swapped for a symlink afterwards.
func TestTrustedDir(t *testing.T) {
	dir := realTempDir(t)
	elsewhere := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "link")))

	_, err := OpenTrustedDir(filepath.Join(dir, "link"), keepID, true)
	require.ErrorContains(t, err, "a symlink is refused")
	_, err = OpenTrustedDir(filepath.Join(dir, "missing"), keepID, false)
	require.ErrorIs(t, err, os.ErrNotExist)

	made := filepath.Join(dir, "config", "agents")
	d, err := OpenTrustedDir(made, keepID, true)
	require.NoError(t, err)
	defer d.Close()
	for _, p := range []string{filepath.Dir(made), made} {
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		require.True(t, fi.IsDir())
		require.Zero(t, fi.Mode().Perm()&0o077, p)
	}

	require.NoError(t, d.WriteFile("bot.url", []byte("one"), 0o600))
	// Swap the opened directory for a symlink: writes, reads and renames
	// still go to the directory held open.
	require.NoError(t, os.Rename(made, made+".held"))
	require.NoError(t, os.Symlink(elsewhere, made))
	require.NoError(t, d.WriteFile("bot.url.pending", []byte("two"), 0o600))
	require.NoError(t, d.Rename("bot.url.pending", "bot.url"))
	f, err := d.OpenFile("bot.url", os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	raw, err := os.ReadFile(filepath.Join(made+".held", "bot.url"))
	require.NoError(t, err)
	require.Equal(t, "two", string(raw))
	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries)

	// A symlink in the directory is refused, for reading and as a write
	// target, and only plain names are accepted.
	require.NoError(t, os.Symlink(filepath.Join(elsewhere, "x"), filepath.Join(made+".held", "planted")))
	_, err = d.OpenFile("planted", os.O_RDONLY, 0)
	require.ErrorContains(t, err, "is a symlink, which is refused")
	require.ErrorContains(t, d.WriteFile("planted", []byte("x"), 0o600), "not a regular file")
	for _, bad := range []string{"", ".", "..", "../x", "a/b"} {
		_, err = d.OpenFile(bad, os.O_RDONLY, 0)
		require.ErrorContains(t, err, "is not a file name", bad)
	}
}
