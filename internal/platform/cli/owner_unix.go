//go:build unix

package cli

import (
	"errors"
	"os"
	"syscall"
)

// InfoOwnerUID is the uid that owns the file fi describes.
func InfoOwnerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// FileOwnerUID is the uid that owns path.
func FileOwnerUID(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no owner in the file's stat")
	}
	return int(st.Uid), nil
}
