//go:build unix

package channel

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path read-only, refusing a symlink (O_NOFOLLOW) and not
// blocking on a FIFO or device (O_NONBLOCK; the regular-file check follows).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkOwner refuses a file or directory this process's effective user
// does not own: the engine creates its keys as its own OS user.
func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file owner")
	}
	if uid := os.Geteuid(); int64(st.Uid) != int64(uid) {
		return fmt.Errorf("owned by uid %d, not by the engine's user (uid %d)", st.Uid, uid)
	}
	return nil
}

// syncDir flushes a directory entry change (a new link) to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
