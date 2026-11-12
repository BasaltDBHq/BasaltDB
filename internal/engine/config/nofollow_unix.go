//go:build unix

package config

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens path read-only without following a symlink at the path,
// and refuses anything but a regular file with one link (a hardlink to a
// root-only file the engine user planted).
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
