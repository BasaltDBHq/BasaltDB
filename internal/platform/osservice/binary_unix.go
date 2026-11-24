//go:build unix

package osservice

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// CheckBinary refuses a binary at path that anyone but root could change
// (see the package CheckBinary), checking both the path the unit names and
// the file it resolves to.
func (OSSystem) CheckBinary(path string) error {
	if err := CheckBinary(path, lstatOwner); err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real == filepath.Clean(path) {
		return err
	}
	return CheckBinary(real, lstatOwner)
}

func lstatOwner(path string) (FileStat, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return FileStat{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileStat{}, errors.New("no owner in the file's stat")
	}
	return FileStat{UID: st.Uid, Mode: fi.Mode()}, nil
}
