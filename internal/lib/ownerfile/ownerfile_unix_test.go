//go:build unix

package ownerfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const secret = "s3cret-value"

func writeSecret(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(secret), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

// requireRefused checks err is the refusal rule and never holds the secret.
func requireRefused(t *testing.T, err error, rule Rule) *RefusedError {
	t.Helper()
	re := Refusal(err)
	require.NotNil(t, re, "%v", err)
	require.Equal(t, rule, re.Rule, "%v", err)
	require.NotContains(t, err.Error(), secret)
	return re
}

func TestReadReadsAnOwnerOnlyFile(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	raw, fi, err := Read(path, Rules{MaxBytes: 64})
	require.NoError(t, err)
	require.Equal(t, secret, string(raw))
	require.Equal(t, int64(len(secret)), fi.Size())

	raw, _, err = Read(writeSecret(t, 0o400), Rules{})
	require.NoError(t, err, "read-only for the owner is narrower than 0600")
	require.Equal(t, secret, string(raw))
}

func TestReadReadsAnEmptyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	raw, _, err := Read(path, Rules{MaxBytes: 64})
	require.NoError(t, err)
	require.Empty(t, raw)
}

func TestReadRefusesASymlink(t *testing.T) {
	t.Parallel()
	target := writeSecret(t, 0o600)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(target, link))
	_, _, err := Read(link, Rules{})
	requireRefused(t, err, Symlink)

	dangling := filepath.Join(t.TempDir(), "dangling")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "gone"), dangling))
	_, _, err = Read(dangling, Rules{})
	requireRefused(t, err, Symlink)
}

func TestReadRefusesASecondHardLink(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	other := filepath.Join(t.TempDir(), "other")
	require.NoError(t, os.Link(path, other))
	for _, p := range []string{path, other} {
		_, _, err := Read(p, Rules{})
		requireRefused(t, err, HardLinks)
		require.EqualError(t, err, "file has more than one hard link")
	}
	require.NoError(t, os.Remove(other))
	_, _, err := Read(path, Rules{})
	require.NoError(t, err, "one link again")
}

func TestReadRefusesAnotherOwner(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	other := os.Geteuid() + 1
	_, _, err := Read(path, Rules{Owners: []int{other}})
	re := requireRefused(t, err, Owner)
	require.Equal(t, os.Geteuid(), re.UID)
	require.EqualError(t, err, "owned by uid "+itoa(os.Geteuid())+", not uid "+itoa(other))

	_, _, err = Read(path, Rules{Owners: []int{other}, OwnerName: "the engine's user"})
	require.EqualError(t, err, "owned by uid "+itoa(os.Geteuid())+", not the engine's user")

	_, _, err = Read(path, Rules{Owners: []int{-1}})
	requireRefused(t, err, Owner)

	_, _, err = Read(path, Rules{Owners: []int{other, os.Geteuid()}})
	require.NoError(t, err, "any named owner")
}

func TestCheckOwnerDefaultsToTheEffectiveUID(t *testing.T) {
	t.Parallel()
	fi, err := os.Stat(writeSecret(t, 0o600))
	require.NoError(t, err)
	st := *fi.Sys().(*syscall.Stat_t)
	require.NoError(t, CheckOwner(statInfo{FileInfo: fi, st: &st}, Rules{}))

	st.Uid = uint32(os.Geteuid() + 1)
	err = CheckOwner(statInfo{FileInfo: fi, st: &st}, Rules{})
	requireRefused(t, err, Owner)
	require.ErrorContains(t, err, "not this process's user (uid "+itoa(os.Geteuid())+")")
}

func TestReadRefusesGroupOrOtherAccess(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o644, 0o666} {
		_, _, err := Read(writeSecret(t, mode), Rules{})
		re := requireRefused(t, err, Mode)
		require.Equal(t, mode, re.Perm)
		require.ErrorContains(t, err, "more open than 0600")
	}
}

func TestReadRefusesATooLargeFile(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	_, _, err := Read(path, Rules{MaxBytes: int64(len(secret)) - 1})
	re := requireRefused(t, err, TooLarge)
	require.Equal(t, int64(len(secret)), re.Size)
	_, _, err = Read(path, Rules{MaxBytes: int64(len(secret))})
	require.NoError(t, err, "exactly the cap")
}

func TestReadRefusesADirectoryAndAFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, err := Read(dir, Rules{})
	requireRefused(t, err, NotRegular)

	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	done := make(chan error, 1)
	go func() {
		_, _, err := Read(fifo, Rules{})
		done <- err
	}()
	select {
	case err := <-done:
		requireRefused(t, err, NotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}

// A device node is refused on what Lstat says, before any open: opening
// one can have side effects.
func TestOpenRefusesADeviceWithoutOpeningIt(t *testing.T) {
	t.Parallel()
	_, _, err := Open("/dev/null", Rules{})
	requireRefused(t, err, NotRegular)
	fi, err := os.Lstat("/dev/null")
	require.NoError(t, err)
	require.NotZero(t, fi.Mode()&os.ModeDevice)
}

// The symlink refusal at the open (ELOOP) still holds when the path is
// swapped for a link after the Lstat.
func TestOpenNoFollowRefusesASymlinkAtTheOpen(t *testing.T) {
	t.Parallel()
	target := writeSecret(t, 0o600)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(target, link))
	_, err := OpenNoFollow(link)
	require.ErrorIs(t, err, syscall.ELOOP)
	require.True(t, isSymlinkErr(err))
}

func TestReadMissingIsNotExist(t *testing.T) {
	t.Parallel()
	_, _, err := Read(filepath.Join(t.TempDir(), "gone"), Rules{})
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Nil(t, Refusal(err))
}

func TestReadOpenChecksTheOpenFile(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o644)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	_, _, err = ReadOpen(f, Rules{})
	requireRefused(t, err, Mode)

	path = writeSecret(t, 0o600)
	g, err := os.Open(path)
	require.NoError(t, err)
	defer g.Close()
	require.NoError(t, os.Link(path, path+".2"))
	_, _, err = ReadOpen(g, Rules{})
	requireRefused(t, err, HardLinks)
	require.NoError(t, os.Remove(path+".2"))
	raw, _, err := ReadOpen(g, Rules{})
	require.NoError(t, err)
	require.Equal(t, secret, string(raw))
}

func TestReadOpenRefusesAFileRemovedAfterTheOpen(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, os.Remove(path))
	_, _, err = ReadOpen(f, Rules{})
	requireRefused(t, err, Unlinked)
}

func TestReadAllRefusesAFileThatChangedSize(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o600)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	fi, err := f.Stat()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(secret+"grown"), 0o600))
	_, err = readAll(f, fi)
	requireRefused(t, err, Changed)

	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	_, err = readAll(f, fi)
	requireRefused(t, err, Changed)
}

func TestReadOrCreateCreatesA0600FileOnceAndKeepsIt(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	fills := 0
	fill := func() ([]byte, error) { fills++; return []byte(secret), nil }
	raw, _, err := ReadOrCreate(path, Rules{MaxBytes: 64}, fill, time.Now)
	require.NoError(t, err)
	require.Equal(t, secret, string(raw))
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, FileMode, fi.Mode().Perm())
	require.EqualValues(t, 1, fi.Sys().(*syscall.Stat_t).Nlink)

	raw, _, err = ReadOrCreate(path, Rules{MaxBytes: 64}, func() ([]byte, error) { return []byte("other"), nil }, time.Now)
	require.NoError(t, err)
	require.Equal(t, secret, string(raw), "an existing file is never replaced")
	require.Equal(t, 1, fills)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left")
}

func TestReadOrCreateRefusesAnExistingBadFileAndLeavesIt(t *testing.T) {
	t.Parallel()
	path := writeSecret(t, 0o644)
	_, _, err := ReadOrCreate(path, Rules{}, func() ([]byte, error) { return []byte("new"), nil }, time.Now)
	requireRefused(t, err, Mode)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, secret, string(raw))
}

func TestReadOrCreateLeavesNothingWhenFillFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	boom := errors.New("no randomness")
	_, _, err := ReadOrCreate(path, Rules{}, func() ([]byte, error) { return nil, boom }, time.Now)
	require.ErrorIs(t, err, boom)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestReadOrCreateKeepsTheFirstOfConcurrentCreates(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	const creates = 16
	got := make([][]byte, creates)
	errs := make([]error, creates)
	var wg sync.WaitGroup
	for i := range creates {
		wg.Go(func() {
			got[i], _, errs[i] = ReadOrCreate(path, Rules{MaxBytes: 64}, func() ([]byte, error) {
				return []byte{byte('a' + i)}, nil
			}, time.Now)
		})
	}
	wg.Wait()
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	for i := range creates {
		require.NoError(t, errs[i], i)
		require.True(t, bytes.Equal(want, got[i]), i)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestReadOrCreateRemovesLeftoverTemps(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(path, []byte(secret), 0o600))
	// A create that stopped between the link and the removal: a second link.
	linked := path + ".111.tmp"
	require.NoError(t, os.Link(path, linked))
	stale := path + ".123.tmp"
	fresh := path + ".456.tmp"
	unrelated := filepath.Join(dir, "other.789.tmp")
	for _, p := range []string{stale, fresh, unrelated} {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	}
	old := time.Now().Add(-2 * staleTempAge)
	require.NoError(t, os.Chtimes(stale, old, old))
	require.NoError(t, os.Chtimes(unrelated, old, old))

	raw, _, err := ReadOrCreate(path, Rules{}, func() ([]byte, error) { return []byte("new"), nil }, time.Now)
	require.NoError(t, err, "the leftover link is removed before the read")
	require.Equal(t, secret, string(raw))
	for p, gone := range map[string]bool{linked: true, stale: true, fresh: false, unrelated: false} {
		_, err := os.Lstat(p)
		if gone {
			require.ErrorIs(t, err, os.ErrNotExist, p)
		} else {
			require.NoError(t, err, p)
		}
	}
}

func TestRefusalTextsHoldNoContent(t *testing.T) {
	t.Parallel()
	for _, e := range []*RefusedError{
		{Rule: Symlink},
		{Rule: NotRegular},
		{Rule: HardLinks},
		{Rule: Owner, UID: 1, Want: "uid 2"},
		{Rule: Mode, Perm: 0o644},
		{Rule: TooLarge, Size: 9, Max: 8},
		{Rule: Changed},
		{Rule: Unlinked},
	} {
		require.NotEmpty(t, e.Error())
		require.False(t, strings.Contains(e.Error(), "refused"), e.Rule)
	}
}

type statInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (s statInfo) Sys() any { return s.st }

func itoa(n int) string { return strconv.Itoa(n) }
