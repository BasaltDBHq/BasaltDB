//go:build unix

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// emptyDirLinks is the link count of an empty directory (. and its name).
const emptyDirLinks = 2

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
	made := true
	if err := unix.Mkdirat(pfd, base, privateDirCreateMode); errors.Is(err, unix.EEXIST) {
		made = false
	} else if err != nil {
		return -1, &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	fd, err := openDirAt(pfd, base, dir)
	if err != nil {
		return -1, err
	}
	if made {
		if err := handDirOver(pfd, fd, owner); err != nil {
			unix.Close(fd)
			return -1, &os.PathError{Op: "chown", Path: dir, Err: err}
		}
	}
	if _, err := checkDir(fd, dir, owner); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// handDirOver gives a directory root just made (fd) to the trusted owner
// when its parent (pfd) is that owner's and the owner is not root: a new
// agents/ in a config directory the engine's user owns is that user's, as
// the files root writes in it are. Through the descriptor, never the path.
func handDirOver(pfd, fd, owner int) error {
	if owner <= 0 {
		return nil
	}
	var st unix.Stat_t
	if err := fstat(pfd, &st); err != nil {
		return err
	}
	if int(st.Uid) != owner {
		return nil
	}
	// Only the directory this process just made: the parent's owner could
	// rename another directory onto the name between the mkdir and the
	// open (one root made earlier, say), which is never given away. A new
	// one is this process's, mode 0700 and empty.
	var made unix.Stat_t
	if err := fstat(fd, &made); err != nil {
		return err
	}
	if int(made.Uid) != os.Geteuid() || statMode(made.Mode)&permBits != privateDirCreateMode || made.Nlink != emptyDirLinks {
		return nil
	}
	return unix.Fchown(fd, owner, keepID)
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
		return nil, symlinkError(full)
	}
	if err != nil {
		return nil, &os.PathError{Op: opOpen, Path: full, Err: err}
	}
	return os.NewFile(uintptr(fd), full), nil
}

// WriteFile writes data to name atomically with mode, owned by owner (this
// process when owner < 0): a new temp file created exclusively in the
// directory, given to owner through its descriptor, then renamed over
// name, which replaces a link rather than following it. A name that is not
// a regular file is refused, as config.WriteFile does. Only the uid
// changes; the group stays the process's.
func (d *TrustedDir) WriteFile(name string, data []byte, mode os.FileMode, owner int) error {
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
	if owner < 0 {
		owner = keepID
	}
	if err := fillTemp(f, data, mode, ownerIDs{uid: owner, gid: keepID}); err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return err
	}
	if err := unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return err
	}
	return nil
}

// symlinkError is a name OpenFile refused for being a symlink; it wraps
// ELOOP, so a caller can tell it apart (config.LockAt: a lock file that
// cannot be used).
type symlinkError string

func (e symlinkError) Error() string { return string(e) + " is a symlink, which is refused" }

func (e symlinkError) Unwrap() error { return unix.ELOOP }

// CreateFile writes data to name only when name does not exist yet: a
// temp file created exclusively in the directory, given mode and owner
// (this process when owner < 0) through its descriptor, then hard-linked
// to name, so name appears whole or not at all and a file made meanwhile
// is kept (an error wrapping fs.ErrExist).
func (d *TrustedDir) CreateFile(name string, data []byte, mode os.FileMode, owner int) error {
	if err := d.name(name); err != nil {
		return err
	}
	f, tmp, err := createTempAt(d.fd, name)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(d.fd, tmp, 0) }()
	if owner < 0 {
		owner = keepID
	}
	if err := fillTemp(f, data, mode, ownerIDs{uid: owner, gid: keepID}); err != nil {
		return err
	}
	if err := unix.Linkat(d.fd, tmp, d.fd, name, 0); err != nil {
		return &os.LinkError{Op: "link", Old: filepath.Join(d.path, tmp), New: filepath.Join(d.path, name), Err: err}
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
