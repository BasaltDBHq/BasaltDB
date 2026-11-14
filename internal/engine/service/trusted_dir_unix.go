//go:build unix

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// privateDirCreateMode is the mode of a directory OpenTrustedDir makes, as
// config.WriteFile makes one.
const privateDirCreateMode = 0o700

// opOpen is the Op of an os.PathError for a failed open.
const opOpen = "open"

// TrustedDir is a directory root opened by openTrusted: every component
// from / reached without following a link anyone but root controls, each
// owned by root or the trusted owner and not writable by group or others.
// Its files are then reached relative to the open descriptor, so swapping
// the directory, or one above it, for a symlink after the open redirects
// nothing.
type TrustedDir struct {
	fd   int
	path string
}

// OpenTrustedDir opens dir for root (openTrusted, owner as there). With
// create, a missing dir and missing directories above it are made, mode
// 0700 and owned by root, each relative to its opened parent.
func OpenTrustedDir(dir string, owner int, create bool) (*TrustedDir, error) {
	dir = filepath.Clean(dir)
	fd, err := openTrusted(dir, owner)
	if err != nil && create && errors.Is(err, unix.ENOENT) {
		fd, err = mkdirTrusted(dir, owner)
	}
	if err != nil {
		return nil, err
	}
	return &TrustedDir{fd: fd, path: dir}, nil
}

// mkdirTrusted makes dir in its parent, opened by openTrusted (made first
// when missing), and opens it without following a link.
func mkdirTrusted(dir string, owner int) (int, error) {
	parent := filepath.Dir(dir)
	if parent == dir {
		return -1, &os.PathError{Op: opOpen, Path: dir, Err: unix.ENOENT}
	}
	pfd, err := openTrusted(parent, owner)
	if errors.Is(err, unix.ENOENT) {
		pfd, err = mkdirTrusted(parent, owner)
	}
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	base := filepath.Base(dir)
	if err := unix.Mkdirat(pfd, base, privateDirCreateMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	fd, err := openDirAt(pfd, base, dir)
	if err != nil {
		return -1, err
	}
	if _, err := checkDir(fd, dir, owner); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Path is the directory's path as opened.
func (d *TrustedDir) Path() string { return d.path }

// Owner is the uid that owns the directory, read through its descriptor.
func (d *TrustedDir) Owner() (int, error) {
	var st unix.Stat_t
	if err := fstat(d.fd, &st); err != nil {
		return 0, err
	}
	return int(st.Uid), nil
}

// Close closes the directory's descriptor.
func (d *TrustedDir) Close() error { return unix.Close(d.fd) }

// name refuses anything but a plain name in the directory.
func (d *TrustedDir) name(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("%q is not a file name in %s", name, d.path)
	}
	return nil
}

// OpenFile opens name in the directory with flag (O_NOFOLLOW and O_CLOEXEC
// added) and perm: a symlink at name is refused, never followed.
func (d *TrustedDir) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if err := d.name(name); err != nil {
		return nil, err
	}
	full := filepath.Join(d.path, name)
	fd, err := unix.Openat(d.fd, name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%s is a symlink, which is refused", full)
	}
	if err != nil {
		return nil, &os.PathError{Op: opOpen, Path: full, Err: err}
	}
	return os.NewFile(uintptr(fd), full), nil
}

// WriteFile writes data to name atomically with mode, owned by this
// process: a new temp file created exclusively in the directory, then
// renamed over name, which replaces a link rather than following it. A
// name that is not a regular file is refused, as config.WriteFile does.
func (d *TrustedDir) WriteFile(name string, data []byte, mode os.FileMode) error {
	if err := d.name(name); err != nil {
		return err
	}
	var st unix.Stat_t
	err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil && statMode(st.Mode)&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%s is not a regular file (a symlink?); refusing to write it", filepath.Join(d.path, name))
	case err != nil && !errors.Is(err, unix.ENOENT):
		return err
	}
	f, tmp, err := createTempAt(d.fd, name)
	if err != nil {
		return err
	}
	if err := fillTemp(f, data, mode, ownerIDs{uid: keepID, gid: keepID}); err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return err
	}
	if err := unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return err
	}
	return nil
}

// Rename renames from over to, both in the directory.
func (d *TrustedDir) Rename(from, to string) error {
	if err := d.name(from); err != nil {
		return err
	}
	if err := d.name(to); err != nil {
		return err
	}
	if err := unix.Renameat(d.fd, from, d.fd, to); err != nil {
		return &os.LinkError{Op: "rename", Old: filepath.Join(d.path, from), New: filepath.Join(d.path, to), Err: err}
	}
	return nil
}
