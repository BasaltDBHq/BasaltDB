//go:build unix

package pluginfs

import (
	"io/fs"
	"syscall"
)

// NoFollow are the open flags that refuse a final symlink and do not block
// on a FIFO or a device: O_NOFOLLOW|O_NONBLOCK.
func (Files) NoFollow() int { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }

// Owner is the uid that owns the file fi describes; false when fi carries
// no owner.
func (Files) Owner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
