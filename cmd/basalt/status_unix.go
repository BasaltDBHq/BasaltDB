//go:build unix

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// fileOwner is the name of the OS user who owns path (its uid when the name
// does not resolve), or "" when it cannot be read.
func fileOwner(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "" // not a Unix file system's stat; the owner is unknown
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}
