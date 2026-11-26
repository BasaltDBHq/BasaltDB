//go:build unix

package pluginfs_test

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginfs"
)

// stepOf is the step an open-file method reports it failed in.
func stepOf(t *testing.T, err error) string {
	t.Helper()
	var pe *fs.PathError
	require.ErrorAs(t, err, &pe)
	return pe.Op
}

var errRefused = errors.New("refused")

func TestReadOpenChecksTheOpenFileBeforeReading(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, []byte("hello"), 0o600))
	files := pluginfs.Files{}

	var seen fs.FileInfo
	b, err := files.ReadOpen(p, os.O_RDONLY|files.NoFollow(), 3, func(fi fs.FileInfo) error {
		seen = fi
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "hel", string(b), "reads at most max bytes")
	require.Equal(t, int64(5), seen.Size())

	b, err = files.ReadOpen(p, os.O_RDONLY, 10, func(fs.FileInfo) error { return errRefused })
	require.ErrorIs(t, err, errRefused, "the check's refusal comes back as it is")
	require.Nil(t, b)

	// A directory is opened and checked, never read.
	_, err = files.ReadOpen(dir, os.O_RDONLY|files.NoFollow(), 10, func(fi fs.FileInfo) error {
		require.True(t, fi.IsDir())
		return errRefused
	})
	require.ErrorIs(t, err, errRefused)
}

func TestReadOpenNamesTheFailedStep(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := pluginfs.Files{}
	missing := filepath.Join(dir, "missing")
	_, err := files.ReadOpen(missing, os.O_RDONLY, 10, nil)
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Equal(t, "open "+missing+": no such file or directory", err.Error())

	// Without a check a directory is read, and the read fails.
	_, err = files.ReadOpen(dir, os.O_RDONLY, 10, nil)
	require.Equal(t, pluginfs.OpRead, stepOf(t, err))

	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	called := false
	_, err = files.ReadOpen(link, os.O_RDONLY|files.NoFollow(), 10, func(fs.FileInfo) error { called = true; return nil })
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
	require.False(t, called, "a symlink is refused at the open, before any check")
}

func TestHashOpenHashesTheCheckedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, []byte("hello"), 0o600))
	files := pluginfs.Files{}
	sum, err := files.HashOpen(p, os.O_RDONLY|files.NoFollow(), func(fi fs.FileInfo) error {
		require.True(t, fi.Mode().IsRegular())
		return nil
	})
	require.NoError(t, err)
	want := sha256.Sum256([]byte("hello"))
	require.Equal(t, want[:], sum)

	_, err = files.HashOpen(p, os.O_RDONLY, func(fs.FileInfo) error { return errRefused })
	require.ErrorIs(t, err, errRefused)

	_, err = files.HashOpen(filepath.Join(dir, "missing"), os.O_RDONLY, func(fs.FileInfo) error { return nil })
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
}

func TestWriteNewCreatesOnlyANewFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	files := pluginfs.Files{}
	require.NoError(t, files.WriteNew(p, []byte("data"), 0o755, true))
	fi, err := os.Lstat(p)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "mode is set on the file, whatever the umask")
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "data", string(raw))

	err = files.WriteNew(p, []byte("other"), 0o644, false)
	require.Equal(t, pluginfs.OpCreate, stepOf(t, err))
	require.ErrorIs(t, err, fs.ErrExist)
	raw, err = os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "data", string(raw))
}

func TestRootCopyOutCopiesTheCheckedFile(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "bin"), []byte("#!/bin/sh\n"), 0o700))
	files := pluginfs.Files{}
	r, err := files.OpenRoot(src)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	out := filepath.Join(dst, "bin")
	err = r.CopyOut("bin", os.O_RDONLY|files.NoFollow(), func(fi fs.FileInfo) (fs.FileMode, error) {
		require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
		return 0o755, nil
	}, out, 0o644)
	require.NoError(t, err)
	fi, err := os.Lstat(out)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, "#!/bin/sh\n", string(raw))

	// A refused check leaves no destination file.
	refusedOut := filepath.Join(dst, "refused")
	err = r.CopyOut("bin", os.O_RDONLY, func(fs.FileInfo) (fs.FileMode, error) { return 0, errRefused }, refusedOut, 0o644)
	require.ErrorIs(t, err, errRefused)
	_, err = os.Lstat(refusedOut)
	require.ErrorIs(t, err, fs.ErrNotExist)

	// An existing destination is never written.
	err = r.CopyOut("bin", os.O_RDONLY, func(fs.FileInfo) (fs.FileMode, error) { return 0o644, nil }, out, 0o644)
	require.Equal(t, pluginfs.OpCreate, stepOf(t, err))

	// A name that leaves the root is refused at the open.
	require.NoError(t, os.WriteFile(filepath.Join(dst, "outside"), []byte("x"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(dst, "outside"), filepath.Join(src, "escape")))
	err = r.CopyOut("escape", os.O_RDONLY, func(fs.FileInfo) (fs.FileMode, error) { return 0o644, nil }, filepath.Join(dst, "escaped"), 0o644)
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
}

func TestRootReadOpenStaysInsideTheRoot(t *testing.T) {
	t.Parallel()
	dir, outside := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "m"), []byte("manifest"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "x"), []byte("x"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(outside, "x"), filepath.Join(dir, "escape")))
	files := pluginfs.Files{}
	r, err := files.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	b, err := r.ReadOpen("m", os.O_RDONLY|files.NoFollow(), 100, func(fi fs.FileInfo) error { return nil })
	require.NoError(t, err)
	require.Equal(t, "manifest", string(b))
	_, err = r.ReadOpen("escape", os.O_RDONLY, 100, nil)
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
	_, err = r.ReadOpen("../x", os.O_RDONLY, 100, nil)
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
}

func TestRootWriteOpenChecksBeforeWriting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := pluginfs.Files{}
	r, err := files.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	require.NoError(t, r.Mkdir("sub", 0o700))
	fi, err := r.Lstat("sub")
	require.NoError(t, err)
	require.True(t, fi.IsDir())

	create := os.O_WRONLY | files.NoFollow() | os.O_CREATE | os.O_EXCL
	require.NoError(t, r.WriteOpen("sub/f", create, 0o600, func(fi fs.FileInfo) error {
		require.Equal(t, int64(0), fi.Size())
		return nil
	}, []byte("ab")))
	appendFlags := os.O_WRONLY | files.NoFollow() | os.O_APPEND
	err = r.WriteOpen("sub/f", appendFlags, 0o600, func(fi fs.FileInfo) error {
		require.Equal(t, int64(2), fi.Size())
		return errRefused
	}, []byte("cd"))
	require.ErrorIs(t, err, errRefused)
	raw, err := os.ReadFile(filepath.Join(dir, "sub", "f"))
	require.NoError(t, err)
	require.Equal(t, "ab", string(raw), "a refused check writes nothing")

	require.NoError(t, r.Chmod("sub/f", 0o700))
	fi, err = r.Lstat("sub/f")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	err = r.WriteOpen("sub/f", create, 0o600, func(fs.FileInfo) error { return nil }, nil)
	require.Equal(t, pluginfs.OpOpen, stepOf(t, err))
	require.True(t, errors.Is(err, fs.ErrExist) || errors.Is(err, syscall.EEXIST))
}

// swapIn renames a file holding other over p: a path check after this
// would see other, the open file is still the original.
func swapIn(t *testing.T, p string, other []byte) {
	t.Helper()
	tmp := p + ".swap"
	require.NoError(t, os.WriteFile(tmp, other, 0o600))
	require.NoError(t, os.Rename(tmp, p))
}

func TestOpenFileStepsUseTheFileCheckedNotTheSwappedPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := pluginfs.Files{}
	p := filepath.Join(dir, "f")

	require.NoError(t, os.WriteFile(p, []byte("original"), 0o600))
	b, err := files.ReadOpen(p, os.O_RDONLY|files.NoFollow(), 100, func(fs.FileInfo) error {
		swapIn(t, p, []byte("swapped"))
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "original", string(b), "ReadOpen reads the file it checked")

	require.NoError(t, os.WriteFile(p, []byte("original"), 0o600))
	sum, err := files.HashOpen(p, os.O_RDONLY|files.NoFollow(), func(fs.FileInfo) error {
		swapIn(t, p, []byte("swapped"))
		return nil
	})
	require.NoError(t, err)
	want := sha256.Sum256([]byte("original"))
	require.Equal(t, want[:], sum, "HashOpen hashes the file it checked")

	r, err := files.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	require.NoError(t, os.WriteFile(p, []byte("original"), 0o600))
	b, err = r.ReadOpen("f", os.O_RDONLY|files.NoFollow(), 100, func(fs.FileInfo) error {
		swapIn(t, p, []byte("swapped"))
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "original", string(b), "FileRoot.ReadOpen reads the file it checked")

	require.NoError(t, os.WriteFile(p, []byte("original"), 0o600))
	out := filepath.Join(t.TempDir(), "copy")
	require.NoError(t, r.CopyOut("f", os.O_RDONLY|files.NoFollow(), func(fs.FileInfo) (fs.FileMode, error) {
		swapIn(t, p, []byte("swapped"))
		return 0o644, nil
	}, out, 0o644))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, "original", string(raw), "CopyOut copies the file it checked")

	// WriteOpen writes to the inode it checked: a second link keeps it
	// reachable after the swap.
	require.NoError(t, os.WriteFile(p, []byte("ab"), 0o600))
	kept := filepath.Join(dir, "kept")
	require.NoError(t, os.Link(p, kept))
	require.NoError(t, r.WriteOpen("f", os.O_WRONLY|files.NoFollow()|os.O_APPEND, 0o600, func(fs.FileInfo) error {
		swapIn(t, p, []byte("swapped"))
		return nil
	}, []byte("cd")))
	raw, err = os.ReadFile(kept)
	require.NoError(t, err)
	require.Equal(t, "abcd", string(raw), "WriteOpen writes to the file it checked")
	raw, err = os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "swapped", string(raw), "the file swapped in is not written")
}

func TestANilCheckSkipsTheCheckExceptForCopyOut(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := pluginfs.Files{}
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))

	sum, err := files.HashOpen(p, os.O_RDONLY, nil)
	require.NoError(t, err)
	want := sha256.Sum256([]byte("x"))
	require.Equal(t, want[:], sum)

	r, err := files.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	require.NoError(t, r.WriteOpen("f", os.O_WRONLY|os.O_APPEND, 0o600, nil, []byte("y")))
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "xy", string(raw))

	// CopyOut takes the copy's mode from its check: without one it opens
	// nothing and creates nothing.
	out := filepath.Join(dir, "copy")
	err = r.CopyOut("f", os.O_RDONLY, nil, out, 0o644)
	require.Error(t, err)
	var pe *fs.PathError
	require.False(t, errors.As(err, &pe), "no step ran")
	_, err = os.Lstat(out)
	require.ErrorIs(t, err, fs.ErrNotExist)
}
