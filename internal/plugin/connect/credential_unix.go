//go:build unix

package connect

import (
	"fmt"
	"os"
	"syscall"
)

// credentialPermMask is the bits the credential file must not have: any
// access for group or others.
const credentialPermMask os.FileMode = 0o077

// openNoFollow opens path read-only, refusing a symlink (O_NOFOLLOW) and not
// blocking on a FIFO or device (O_NONBLOCK; the regular-file check follows).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkCredentialFileInfo returns the rule the opened file breaks, or "":
// it must belong to the engine's user and be readable by that user only.
func checkCredentialFileInfo(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "has no owner the engine can read"
	}
	if uid := os.Getuid(); int64(st.Uid) != int64(uid) {
		return fmt.Sprintf("is owned by uid %d, not by the engine's user (uid %d)", st.Uid, uid)
	}
	if perm := fi.Mode().Perm(); perm&credentialPermMask != 0 {
		return fmt.Sprintf("is mode %o; it must be readable by the engine's user only (0600)", perm)
	}
	return ""
}
