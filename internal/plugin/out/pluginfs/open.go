package pluginfs

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
)

// The steps an open-file method reports in the Op of the *fs.PathError it
// returns when that step fails, whatever os call failed in it. An error the
// caller's check returns comes back as it is.
const (
	OpOpen   = "open"   // opening the file to read, or to write in a Root
	OpStat   = "stat"   // Stat on the open file
	OpRead   = "read"   // reading it (for CopyOut, copying it, either side)
	OpCreate = "create" // creating the new file a write goes to
	OpWrite  = "write"  // writing, Chmod, Sync or Close of the file written
)

// FileRoot is a directory opened once as an os.Root: every name is resolved
// inside it, and each method opens, uses and closes its file within the
// call. It is an alias of an interface literal so plugin.FileRoot, the same
// literal, is the same type.
type FileRoot = interface {
	// Lstat is os.Root.Lstat.
	Lstat(name string) (fs.FileInfo, error)
	// Mkdir is os.Root.Mkdir.
	Mkdir(name string, perm fs.FileMode) error
	// Chmod is os.Root.Chmod.
	Chmod(name string, mode fs.FileMode) error
	// ReadOpen is Files.ReadOpen on name inside the root.
	ReadOpen(name string, flag int, most int64, check func(fs.FileInfo) error) ([]byte, error)
	// CopyOut opens name inside the root with flag and Stats that open
	// file; check, which is required (nil is refused before anything is
	// opened), gets its details and returns the mode of the copy. It
	// then creates dst (outside the root, O_EXCL, perm), copies the open
	// file into it, sets mode on the new file, syncs and closes it.
	CopyOut(name string, flag int, check func(fs.FileInfo) (fs.FileMode, error), dst string, perm fs.FileMode) error
	// WriteOpen opens name inside the root with flag and perm, Stats that
	// open file, runs check on its details (no Stat and no check when check
	// is nil) and, when check passes, writes data to it.
	WriteOpen(name string, flag int, perm fs.FileMode, check func(fs.FileInfo) error, data []byte) error
	// Close closes the root.
	Close() error
}

// OpenRoot opens dir as an os.Root.
func (Files) OpenRoot(dir string) (FileRoot, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return root{r}, nil
}

// ReadOpen opens name with flag and reads it on that one open file: Stat,
// check on its details (skipped, with the Stat, when check is nil), then a
// read of up to most bytes, then Close. Nothing is read when check refuses.
func (Files) ReadOpen(name string, flag int, most int64, check func(fs.FileInfo) error) ([]byte, error) {
	f, err := os.OpenFile(name, flag, 0)
	if err != nil {
		return nil, stepError(OpOpen, name, err)
	}
	defer func() { _ = f.Close() }()
	return readChecked(f, name, most, check)
}

// HashOpen opens name with flag, Stats the open file, runs check on its
// details (no Stat and no check when check is nil) and returns the SHA-256
// of the whole open file, then closes it.
func (Files) HashOpen(name string, flag int, check func(fs.FileInfo) error) ([]byte, error) {
	f, err := os.OpenFile(name, flag, 0)
	if err != nil {
		return nil, stepError(OpOpen, name, err)
	}
	defer func() { _ = f.Close() }()
	if err := statChecked(f, name, check); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, stepError(OpRead, name, err)
	}
	return h.Sum(nil), nil
}

// WriteNew creates name, which must not exist (O_EXCL, mode), writes data
// to it, sets mode on it, syncs it when sync is set and closes it.
func (Files) WriteNew(name string, data []byte, mode fs.FileMode, sync bool) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return stepError(OpCreate, name, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return stepError(OpWrite, name, err)
	}
	return finishWrite(f, name, mode, sync)
}

type root struct{ r *os.Root }

func (r root) Lstat(name string) (fs.FileInfo, error)    { return r.r.Lstat(name) }
func (r root) Mkdir(name string, perm fs.FileMode) error { return r.r.Mkdir(name, perm) }
func (r root) Chmod(name string, mode fs.FileMode) error { return r.r.Chmod(name, mode) }
func (r root) Close() error                              { return r.r.Close() }

func (r root) ReadOpen(name string, flag int, most int64, check func(fs.FileInfo) error) ([]byte, error) {
	f, err := r.r.OpenFile(name, flag, 0)
	if err != nil {
		return nil, stepError(OpOpen, name, err)
	}
	defer func() { _ = f.Close() }()
	return readChecked(f, name, most, check)
}

func (r root) CopyOut(name string, flag int, check func(fs.FileInfo) (fs.FileMode, error), dst string, perm fs.FileMode) error {
	if check == nil {
		return errNoCheck
	}
	in, err := r.r.OpenFile(name, flag, 0)
	if err != nil {
		return stepError(OpOpen, name, err)
	}
	defer func() { _ = in.Close() }()
	fi, err := in.Stat()
	if err != nil {
		return stepError(OpStat, name, err)
	}
	mode, err := check(fi)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return stepError(OpCreate, dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return stepError(OpRead, name, err)
	}
	return finishWrite(out, dst, mode, true)
}

func (r root) WriteOpen(name string, flag int, perm fs.FileMode, check func(fs.FileInfo) error, data []byte) error {
	f, err := r.r.OpenFile(name, flag, perm)
	if err != nil {
		return stepError(OpOpen, name, err)
	}
	defer func() { _ = f.Close() }()
	if err := statChecked(f, name, check); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return stepError(OpWrite, name, err)
	}
	return nil
}

// errNoCheck: CopyOut takes the copy's mode from its check, so it needs one.
var errNoCheck = errors.New("pluginfs: CopyOut needs a check")

// statChecked Stats the open file f and runs check on its details; with no
// check it does neither.
func statChecked(f *os.File, name string, check func(fs.FileInfo) error) error {
	if check == nil {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return stepError(OpStat, name, err)
	}
	return check(fi)
}

// readChecked runs statChecked on f and reads up to most bytes from it.
func readChecked(f *os.File, name string, most int64, check func(fs.FileInfo) error) ([]byte, error) {
	if err := statChecked(f, name, check); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, most))
	if err != nil {
		return nil, stepError(OpRead, name, err)
	}
	return b, nil
}

// finishWrite sets mode on f, syncs it when sync is set and closes it; f is
// closed whatever fails.
func finishWrite(f *os.File, name string, mode fs.FileMode, sync bool) error {
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return stepError(OpWrite, name, err)
	}
	if sync {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return stepError(OpWrite, name, err)
		}
	}
	if err := f.Close(); err != nil {
		return stepError(OpWrite, name, err)
	}
	return nil
}

// stepError is err as the failure of step on name: an *fs.PathError whose
// Op is step, wrapping the os error's own cause so its text reads as the os
// call's ("open name: no such file or directory").
func stepError(step, name string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return &fs.PathError{Op: step, Path: name, Err: err}
}
