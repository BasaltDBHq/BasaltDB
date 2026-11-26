//go:build unix && !(linux && amd64)

package pluginfs

import (
	"io/fs"
	"syscall"
)

// Links is the hard link count of the file fi describes; false when fi
// carries none. Stat_t.Nlink is narrower than uint64 here
// (darwin, the BSDs, linux on arm64); on linux/amd64 it is uint64.
func (Files) Links(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
