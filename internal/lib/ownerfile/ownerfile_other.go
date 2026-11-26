//go:build !unix

package ownerfile

import (
	"os"
)

// checksModes: outside Unix the permission bits do not say who can read a
// file (an ACL does), so they are not checked.
const checksModes = false

// OpenNoFollow opens path read-only. Outside Unix there is no O_NOFOLLOW:
// a link at the path is refused by an Lstat before the open, and a path
// swapped for another file between the two by SameFile after it.
func OpenNoFollow(path string) (*os.File, error) {
	link, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: errSymlink}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !os.SameFile(link, fi) {
		err = &os.PathError{Op: "open", Path: path, Err: errSymlink}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

type symlinkError struct{}

func (symlinkError) Error() string { return "a symbolic link" }

var errSymlink error = symlinkError{}

func isSymlinkErr(err error) bool {
	pe, ok := err.(*os.PathError)
	return ok && pe.Err == errSymlink
}

// CheckPlain refuses anything but a regular file. Links are counted on Unix
// only.
func CheckPlain(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return &RefusedError{Rule: NotRegular}
	}
	return nil
}

// unlinked: links are counted on Unix only.
func unlinked(os.FileInfo) bool { return false }

// CheckOwner is a no-op outside Unix: ownership is an ACL there.
func CheckOwner(os.FileInfo, Rules) error { return nil }
