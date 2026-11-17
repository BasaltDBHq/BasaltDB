//go:build unix

package binwatch

import (
	"errors"
	"os"
	"syscall"
)

// Stat follows symlinks: the identity of the file path leads to.
func (OS) Stat(path string) (Identity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Identity{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, errors.New("no inode in the file's stat")
	}
	return Identity{
		Dev: uint64(st.Dev), Ino: st.Ino, //nolint:unconvert // Dev is int32 on darwin
		Size: fi.Size(), ModNanos: fi.ModTime().UnixNano(), Mode: uint32(fi.Mode()),
	}, nil
}

// Exec replaces this process with the binary at path, with the same
// arguments and environment: the same process id, OS user, groups, umask
// and (on Linux) no_new_privs, which a running process cannot widen.
func Exec(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}
