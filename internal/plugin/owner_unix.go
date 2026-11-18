//go:build unix

package plugin

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

var errNoOwner = errors.New("the file owner cannot be read")

// fileOwner is the uid that owns the file fi describes.
func fileOwner(fi fs.FileInfo) (uint32, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errNoOwner
	}
	return st.Uid, nil
}

// currentUID is this process's effective uid: the engine's own user.
func currentUID() (uint32, error) {
	uid := os.Geteuid()
	if uid < 0 {
		return 0, errNoOwner
	}
	return uint32(uid), nil
}

// noFollowFlags open a file read-only without following a final symlink and
// without blocking on a FIFO or a device; the caller checks it is regular.
const noFollowFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
