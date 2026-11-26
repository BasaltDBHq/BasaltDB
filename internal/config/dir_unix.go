//go:build unix

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// LockAt is LockFile on the lock file name in d, a directory a root process
// opened without following a link (Dir): opened relative to d, never
// through a symlink, and a root-owned lock file is handed to d's owner as
// LockFile does. A lock file that cannot be opened or used (a symlink, a
// hard link, no permission) is a *LockUnusableError.
func LockAt(d Dir, name string) (func(), error) {
	path := filepath.Join(d.Path(), name)
	owner, err := d.Owner()
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	f, err := d.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NONBLOCK, FileMode)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EMLINK) {
			return nil, &LockUnusableError{Path: path, Err: err}
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return LockOpenFile(f, owner)
}

// OpenPlainAt opens name in d read-only, without following a link or
// blocking on a FIFO, refuses anything but a regular file with one link,
// then runs check (when not nil) on the open file.
func OpenPlainAt(d Dir, name string, check func(*os.File) error) (*os.File, error) {
	f, err := d.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", f.Name(), err)
	}
	if check != nil {
		if err := check(f); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

// CheckTrustedConfig checks an engine config a root process opened before
// it is read: owned by root or trusted (its directory's owner), not
// writable by group or others.
func CheckTrustedConfig(f *os.File, trusted int) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := CheckPlainFile(fi); err != nil {
		return fmt.Errorf("%s: %w", f.Name(), err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file's owner")
	}
	if uid := int(st.Uid); uid != rootUID && uid != trusted {
		return fmt.Errorf("%s is owned by uid %d, not root or uid %d (its directory's owner)", f.Name(), uid, trusted)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o), so another user could change what root trusts in it; "+
			"remove that access (sudo chmod go-w %s)", f.Name(), perm, f.Name())
	}
	return nil
}

// ReadCredentialAt reads the credential file name in d for a root process:
// a regular file with one link, opened without following a link, mode 0600
// or tighter, owned by this process's user or by d's owner (the engine's
// user, whom basalt init --remote hands the files to). It returns the
// connection string and the file's info, so a later rename can check the
// name still names the file read (SameFileAt).
func ReadCredentialAt(d Dir, name string) (string, os.FileInfo, error) {
	return ReadCredentialAtLimit(d, name, maxConfigBytes)
}

// ReadCredentialAtLimit is ReadCredentialAt for a file of at most limit
// bytes, counted as stored (before the surrounding space is trimmed). The
// checks are ownerfile's, on the file opened relative to d.
func ReadCredentialAtLimit(d Dir, name string, limit int) (string, os.FileInfo, error) {
	path := filepath.Join(d.Path(), name)
	owner, err := d.Owner()
	if err != nil {
		return "", nil, err
	}
	f, err := d.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	rules := ownerfile.Rules{
		Owners:    []int{os.Geteuid(), owner},
		OwnerName: fmt.Sprintf("this process's user or uid %d (the owner of %s)", owner, d.Path()),
		MaxBytes:  int64(limit),
	}
	raw, fi, err := ownerfile.ReadOpen(f, rules)
	defer clear(raw)
	return credentialText(path, raw, fi, err)
}

// SameFileAt reports whether name in d still names the file fi describes,
// a regular file with one link (SameCredentialFile relative to d).
func SameFileAt(d Dir, name string, fi os.FileInfo) error {
	f, err := OpenPlainAt(d, name, nil)
	if err != nil {
		return err
	}
	defer f.Close()
	now, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(now, fi) {
		return fmt.Errorf("%s changed since it was read", f.Name())
	}
	return nil
}
