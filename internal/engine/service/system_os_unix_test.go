//go:build unix

package service

import (
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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
	require.ErrorContains(t, OSSystem{}.Mkdir(file, 0o700, ""), file+" is not a directory")
}

// A regular file in a middle component is named as what it is.
func TestOSSystemRefusesFileInMiddleComponent(t *testing.T) {
	dir := realTempDir(t)
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	err := OSSystem{}.WriteFile(filepath.Join(file, "agents", "bot.url"), []byte("x"), 0o600, "")
	require.ErrorContains(t, err, file+" is not a directory")
	require.NotContains(t, err.Error(), "symlink")
	require.ErrorContains(t, OSSystem{}.Mkdir(filepath.Join(file, "agents"), 0o700, ""), file+" is not a directory")
}

func TestOpenTrustedFile(t *testing.T) {
	dir := realTempDir(t)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "real"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real", "f"), []byte("ok"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")))
	require.NoError(t, os.Symlink(filepath.Join(dir, "real", "f"), filepath.Join(dir, "real", "g")))

	f, err := OpenTrustedFile(filepath.Join(dir, "real", "f"), keepID)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = OpenTrustedFile(filepath.Join(dir, "link", "f"), keepID)
	require.ErrorContains(t, err, "a symlink is refused")
	_, err = OpenTrustedFile(filepath.Join(dir, "real", "g"), keepID)
	require.ErrorContains(t, err, "is a symlink, which is refused")
	_, err = OpenTrustedFile(filepath.Join(dir, "real", "missing"), keepID)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// testPolicy lets the test user stand in for root: tests cannot run as
// root, so directories the test user owns (and a sticky /tmp) count as
// root's.
func testPolicy() trustPolicy {
	return trustPolicy{rootUIDs: []uint32{0, uint32(os.Getuid())}, stickyOK: true}
}

func TestMain(m *testing.M) {
	dirPolicy = testPolicy()
	os.Exit(m.Run())
}

// rootOnly trusts only uid 0, as a real install does, for one test.
func rootOnly(t *testing.T) {
	t.Helper()
	dirPolicy.rootUIDs = []uint32{0}
	t.Cleanup(func() { dirPolicy = testPolicy() })
}

// realTempDir is t.TempDir with symlinks resolved (macOS /var is one), as
// the install names directories in its errors.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

// ownedBy makes the directory at path look owned by uid to the install.
func ownedBy(t *testing.T, path string, uid uint32) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	ino := fi.Sys().(*syscall.Stat_t).Ino
	fstat = func(fd int, st *unix.Stat_t) error {
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		if st.Ino == ino {
			st.Uid = uid
		}
		return nil
	}
	t.Cleanup(func() { fstat = unix.Fstat })
}

// The engine user owns the config directory x once it is made (and its
// parent too when an earlier install put the config there), so it can swap
// x for a symlink to elsewhere. Root must not follow x to make, chown or
// write into elsewhere/agents.
func TestOSSystemRefusesSymlinkInMiddleComponent(t *testing.T) {
	dir := t.TempDir()
	cur, err := user.Current()
	require.NoError(t, err)
	x := filepath.Join(dir, "x")
	require.NoError(t, OSSystem{}.Mkdir(x, 0o755, cur.Username))
	elsewhere := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.MkdirAll(filepath.Join(elsewhere, "agents"), 0o755))
	require.NoError(t, os.Chmod(filepath.Join(elsewhere, "agents"), 0o755))
	require.NoError(t, os.Rename(x, filepath.Join(dir, "moved")))
	require.NoError(t, os.Symlink(elsewhere, x))

	require.ErrorContains(t, OSSystem{}.Mkdir(filepath.Join(x, "agents"), 0o700, cur.Username), "symlink is refused")
	require.ErrorContains(t, OSSystem{}.WriteFile(filepath.Join(x, "agents", "bot.url"), []byte("secret"), 0o600, cur.Username), "symlink is refused")
	require.ErrorContains(t, OSSystem{}.Mkdir(filepath.Join(x, "agents", "deeper"), 0o700, cur.Username), "symlink is refused")

	fi, err := os.Stat(filepath.Join(elsewhere, "agents"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "the link target keeps its mode")
	entries, err := os.ReadDir(filepath.Join(elsewhere, "agents"))
	require.NoError(t, err)
	require.Empty(t, entries, "nothing is written or made through the link")
}

func TestOSSystemRefusesGroupWritableAncestor(t *testing.T) {
	dir := realTempDir(t)
	shared := filepath.Join(dir, "shared")
	require.NoError(t, os.MkdirAll(filepath.Join(shared, "agents"), 0o700))
	require.NoError(t, os.Chmod(shared, 0o775))

	err := OSSystem{}.WriteFile(filepath.Join(shared, "agents", "bot.url"), []byte("x"), 0o600, "")
	require.ErrorContains(t, err, shared+" is writable by group or others")
	require.ErrorContains(t, err, "sudo chmod go-w "+shared)
	require.ErrorContains(t, OSSystem{}.Mkdir(filepath.Join(shared, "new"), 0o700, ""), shared+" is writable by group or others")
	_, err = os.Stat(filepath.Join(shared, "new"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestOSSystemRefusesAncestorOwnedByAnotherUser(t *testing.T) {
	dir := realTempDir(t)
	theirs := filepath.Join(dir, "theirs")
	require.NoError(t, os.MkdirAll(filepath.Join(theirs, "agents"), 0o700))
	ownedBy(t, theirs, 4242)

	err := OSSystem{}.WriteFile(filepath.Join(theirs, "agents", "bot.url"), []byte("x"), 0o600, "")
	require.ErrorContains(t, err, theirs+" is owned by uid 4242, not root")
	require.ErrorContains(t, OSSystem{}.Mkdir(filepath.Join(theirs, "new"), 0o700, ""), theirs+" is owned by uid 4242")
}

// With only root trusted, as in a real install, a directory a person owns
// is refused, except for files the install gives to that same user: the
// engine's credential goes into agents below its own config directory.
func TestOSSystemRootOnlyAllowsTheOwnersDirectories(t *testing.T) {
	rootOnly(t)
	dir := t.TempDir()
	cur, err := user.Current()
	require.NoError(t, err)

	err = OSSystem{}.WriteFile(filepath.Join(dir, "engine.json"), []byte("x"), 0o600, "")
	require.ErrorContains(t, err, "could redirect what root writes below it")
	require.NoError(t, OSSystem{}.WriteFile(filepath.Join(dir, "engine.json"), []byte("x"), 0o600, cur.Username))
}

func TestOSSystemMkdirRefusesExistingDirOwnedByAnotherUser(t *testing.T) {
	dir := t.TempDir()
	cur, err := user.Current()
	require.NoError(t, err)
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.Mkdir(agents, 0o755))
	require.NoError(t, os.Chmod(agents, 0o755))
	ownedBy(t, agents, 4242)

	err = OSSystem{}.Mkdir(agents, 0o700, cur.Username)
	require.ErrorContains(t, err, agents+" already exists and is owned by uid 4242, not root or "+cur.Username)
	fi, err := os.Stat(agents)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "a refused directory is left as it was")
}
