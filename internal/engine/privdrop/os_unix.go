//go:build linux || darwin

package privdrop

import (
	"errors"
	"syscall"
)

// Umask sets the file mode creation mask.
func (OS) Umask(mask int) { syscall.Umask(mask) }

// Setgroups sets the supplementary groups (on Linux, on every thread).
func (OS) Setgroups(gids []uint32) error {
	ids := make([]int, 0, len(gids))
	for _, g := range gids {
		ids = append(ids, int(g))
	}
	return syscall.Setgroups(ids)
}

// Setgid sets the real, effective and saved group id (on Linux, on every
// thread: Go applies it to all of them).
func (OS) Setgid(gid uint32) error { return syscall.Setgid(int(gid)) }

// Setuid sets the real, effective and saved user id (on Linux, on every
// thread), which also clears every capability.
func (OS) Setuid(uid uint32) error { return syscall.Setuid(int(uid)) }

// errRegained is a drop that root could take back.
var errRegained = errors.New("could regain root after the drop")

// cannotRegain tries to take root back and fails when it can. setuid(0)
// succeeds when the real or saved uid is still 0, seteuid(0) when either
// is; the gid calls the same for the group.
func cannotRegain() error {
	if syscall.Setuid(0) == nil || syscall.Seteuid(0) == nil {
		return errRegained
	}
	if syscall.Setgid(0) == nil || syscall.Setegid(0) == nil {
		return errRegained
	}
	return nil
}
