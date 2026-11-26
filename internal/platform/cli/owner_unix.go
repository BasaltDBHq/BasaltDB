//go:build unix

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// InfoOwnerUID is the uid that owns the file fi describes.
func InfoOwnerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// CheckConfigFile checks the opened config before it is read: a plain
// file, owned by root or trusted, not writable by group or others.
func CheckConfigFile(f *os.File, trusted int) error {
	return config.CheckTrustedConfig(f, trusted)
}

// DirOwner is the owner of path's directory, not following a link.
func DirOwner(path string) (int, error) {
	fi, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read the directory's owner")
	}
	return int(st.Uid), nil
}

// PathOwner is the uid that owns path, following a link.
func PathOwner(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no owner for " + path)
	}
	return int(st.Uid), nil
}
