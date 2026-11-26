//go:build unix

package ownerfile

import (
	"errors"
	"os"
	"syscall"
)

// checksModes: permission bits mean the same as on Unix.
const checksModes = true

// OpenNoFollow opens path read-only without following a symbolic link at
// the path (the open fails with ELOOP) and without blocking on a FIFO or
// device (O_NONBLOCK). It checks nothing else: Open does.
func OpenNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func isSymlinkErr(err error) bool { return errors.Is(err, syscall.ELOOP) }

// CheckPlain refuses anything but a regular file with a single link.
func CheckPlain(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return &RefusedError{Rule: NotRegular}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot stat the file")
	}
	if st.Nlink > 1 {
		return &RefusedError{Rule: HardLinks}
	}
	return nil
}

// unlinked reports an open file with no name left.
func unlinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 0
}

// CheckOwner refuses a file or directory none of r's owners owns.
func CheckOwner(fi os.FileInfo, r Rules) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file's owner")
	}
	for _, o := range r.owners() {
		if o >= 0 && uint64(st.Uid) == uint64(o) {
			return nil
		}
	}
	return &RefusedError{Rule: Owner, UID: int(st.Uid), Want: r.want()}
}
