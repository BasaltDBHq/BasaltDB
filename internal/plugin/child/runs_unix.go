//go:build unix

package child

import (
	"io/fs"
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

// ownedByMe: fi belongs to the engine's effective user.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// killGroupID sends SIGKILL to the process group pgid leads, and to pgid
// itself in case it left that group.
func killGroupID(pgid int) error {
	errGroup := syscall.Kill(-pgid, syscall.SIGKILL)
	errLeader := syscall.Kill(pgid, syscall.SIGKILL)
	if errGroup != nil && errLeader != nil {
		return errGroup
	}
	return nil
}

func getpgrp() int { return syscall.Getpgrp() }
