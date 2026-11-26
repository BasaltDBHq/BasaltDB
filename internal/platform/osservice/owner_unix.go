//go:build unix

package osservice

import (
	"errors"
	"os"
	"syscall"
)

// fileOwnerUID is the uid that owns path, following a link.
func fileOwnerUID(path string) (int, error) {
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
