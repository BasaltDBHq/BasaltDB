//go:build unix

package service

import (
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOSSystemWriteFileDoesNotFollowFileSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))
	target := filepath.Join(dir, "agents", "bot.url")
	require.NoError(t, os.Mkdir(filepath.Dir(target), 0o700))
	require.NoError(t, os.Symlink(victim, target))

	require.NoError(t, OSSystem{}.WriteFile(target, []byte("new"), 0o600, ""))

	got, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, "keep", string(got), "the symlink target must be untouched")
	fi, err := os.Lstat(target)
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular(), "the link is replaced by a regular file")
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	got, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
	entries, err := os.ReadDir(filepath.Dir(target))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temp file is left behind")
}

func TestOSSystemWriteFileDanglingSymlinkNotCreated(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	target := filepath.Join(dir, "bot.url")
	require.NoError(t, os.Symlink(missing, target))

	require.NoError(t, OSSystem{}.WriteFile(target, []byte("new"), 0o600, ""))

	_, err := os.Lstat(missing)
	require.ErrorIs(t, err, os.ErrNotExist, "nothing is created through a dangling link")
}

// A hardlink to a root file (sudoers on macOS) planted in the directory is
// replaced, not written through or re-owned: the other name keeps its inode.
func TestOSSystemWriteFileHardlinkLeavesOtherNameAlone(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o400))
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.Mkdir(agents, 0o700))
	target := filepath.Join(agents, "bot.url")
	require.NoError(t, os.Link(victim, target))
	before, err := os.Stat(victim)
	require.NoError(t, err)

	cur, err := user.Current()
	require.NoError(t, err)
	require.NoError(t, OSSystem{}.WriteFile(target, []byte("new"), 0o600, cur.Username))

	after, err := os.Stat(victim)
	require.NoError(t, err)
	require.Equal(t, before.Mode(), after.Mode(), "the other name keeps its mode")
	require.EqualValues(t, 1, after.Sys().(*syscall.Stat_t).Nlink, "the planted link is gone")
	got, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, "keep", string(got))
	got, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
}

func TestOSSystemWriteFileRefusesSymlinkedDir(t *testing.T) {
	dir := t.TempDir()
	linked := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(linked, 0o700))
	link := filepath.Join(dir, "agents")
	require.NoError(t, os.Symlink(linked, link))

	err := OSSystem{}.WriteFile(filepath.Join(link, "bot.url"), []byte("x"), 0o600, "")

	require.ErrorContains(t, err, "symlink is refused")
	entries, rerr := os.ReadDir(linked)
	require.NoError(t, rerr)
	require.Empty(t, entries, "nothing is written through the linked directory")
}

// The engine user swaps the directory for a symlink after it was checked:
// the write still lands in the held directory, never in the link's target.
func TestOSSystemWriteFileDirSwappedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.Mkdir(agents, 0o700))
	elsewhere := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	moved := filepath.Join(dir, "moved")

	afterDirOpen = func() {
		require.NoError(t, os.Rename(agents, moved))
		require.NoError(t, os.Symlink(elsewhere, agents))
	}
	t.Cleanup(func() { afterDirOpen = nil })

	require.NoError(t, OSSystem{}.WriteFile(filepath.Join(agents, "bot.url"), []byte("secret"), 0o600, ""))

	entries, err := os.ReadDir(elsewhere)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing lands in the symlink's target")
	got, err := os.ReadFile(filepath.Join(moved, "bot.url"))
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestOSSystemMkdir(t *testing.T) {
	dir := t.TempDir()
	cur, err := user.Current()
	require.NoError(t, err)

	made := filepath.Join(dir, "agents")
	require.NoError(t, OSSystem{}.Mkdir(made, 0o700, cur.Username))
	fi, err := os.Lstat(made)
	require.NoError(t, err)
	require.True(t, fi.IsDir())
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	require.NoError(t, os.Chmod(made, 0o755))
	require.NoError(t, OSSystem{}.Mkdir(made, 0o700, ""), "an existing real directory is taken over")
	fi, err = os.Lstat(made)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestOSSystemMkdirRefusesSymlinkAndFile(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	link := filepath.Join(dir, "agents")
	require.NoError(t, os.Symlink(realDir, link))

	require.ErrorContains(t, OSSystem{}.Mkdir(link, 0o700, ""), "not a real directory")
	fi, err := os.Stat(realDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "the link target keeps its mode")

	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	require.ErrorContains(t, OSSystem{}.Mkdir(file, 0o700, ""), "not a real directory")
}
