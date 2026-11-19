//go:build unix

package dial

import (
	"os"
	"syscall"
)

// SocketDirIs reports whether dir, not followed if it is a link, is a
// directory owned by uid, in group gid, with no permission bit for others.
func SocketDirIs(dir string, uid, gid uint32) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && st.Gid == gid && fi.Mode().Perm()&0o007 == 0
}
