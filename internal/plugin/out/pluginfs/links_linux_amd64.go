//go:build linux && amd64

package pluginfs

import (
	"io/fs"
	"syscall"
)

// Links is the hard link count of the file fi describes; false when fi
// carries none.
func (Files) Links(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Nlink, true
}
