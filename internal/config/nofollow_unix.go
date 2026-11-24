//go:build unix

package config

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path read-only without following a symlink at the path
// and without blocking on a FIFO or device (O_NONBLOCK), and refuses anything
// but a regular file with one link (a hardlink to a root-only file the engine
// user planted).
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// CheckPlainFile refuses anything but a regular file with a single link.
func CheckPlainFile(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot stat the file")
	}
	if st.Nlink > 1 {
		return errors.New("file has more than one hard link")
	}
	return nil
}

// openCredential opens the credential file at path as openNoFollow does, and
// refuses a symlink, anything but a regular file with one link, and a file
// owned by anyone but this process's user or root, each named with the path.
// A missing file stays fs.ErrNotExist.
func openCredential(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("credential file %s is a symbolic link; the engine reads only a regular file at that path, so replace the link with the file itself", path)
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
		if err != nil {
			err = fmt.Errorf("credential file %s: %w", path, err)
		}
	}
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			err = errors.New("cannot read the owner of credential file " + path)
		} else {
			err = checkCredentialOwner(path, int(st.Uid), os.Geteuid())
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// checkCredentialOwner refuses a credential file owned by uid when uid is
// neither euid, this process's effective user, nor root.
func checkCredentialOwner(path string, uid, euid int) error {
	if uid != euid && uid != rootUID {
		return fmt.Errorf("credential file %s is owned by uid %d, not this process's user or root", path, uid)
	}
	return nil
}
