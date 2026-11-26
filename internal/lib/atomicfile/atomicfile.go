// Package atomicfile replaces a file whole: a reader sees the old file or the
// new one, never half of it.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Options sets what Write and WriteFunc do beyond the replace itself.
type Options struct {
	// Mode is the permission bits of the new file. It is applied with Chmod,
	// so the umask does not narrow it.
	Mode os.FileMode
	// SyncDir also syncs the directory after the rename, so the new name
	// survives a crash.
	SyncDir bool
	// RefuseNonRegular refuses a path that exists and is not a regular file
	// (a symlink, a directory). The rename would replace a link rather than
	// follow it, so this is a guard on top, not the only protection.
	RefuseNonRegular bool
}

// Write replaces path with data.
func Write(path string, data []byte, o Options) error {
	return WriteFunc(path, o, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// WriteFunc replaces path with what write puts in the file. It writes a new
// temporary file next to path (created O_EXCL with a random name, so never
// through a planted link), sets the mode, syncs it, and renames it over path.
// The temporary file is removed on every failure, and the old file is left
// untouched. The directory must exist.
func WriteFunc(path string, o Options, write func(f *os.File) error) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if o.RefuseNonRegular {
		if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file (a symlink?); refusing to write it", path)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // gone after the rename; cleans up after a failure
	if err := fill(tmp, o.Mode, write); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if o.SyncDir {
		return SyncDir(dir)
	}
	return nil
}

func fill(tmp *os.File, mode os.FileMode, write func(f *os.File) error) error {
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}
