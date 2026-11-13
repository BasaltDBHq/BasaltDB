package privdrop

import (
	"fmt"
	"syscall"
)

// NoNewPrivs does nothing on macOS, which has no no_new_privs: a setuid
// binary the engine ran could still gain privileges. The engine runs no
// other program, and launchd gives the installed service no more.
func (OS) NoNewPrivs() error { return nil }

// Verify checks the process's real and effective ids and groups are a's
// (macOS credentials belong to the process, not to each thread), then that
// setuid(0) and setgid(0) fail, which proves the saved ids are not 0 either.
func (OS) Verify(a Account) error {
	uid, euid, gid, egid := syscall.Getuid(), syscall.Geteuid(), syscall.Getgid(), syscall.Getegid()
	if uid != int(a.UID) || euid != int(a.UID) || gid != int(a.GID) || egid != int(a.GID) {
		return fmt.Errorf("uid %d euid %d gid %d egid %d, want uid %d gid %d", uid, euid, gid, egid, a.UID, a.GID)
	}
	groups, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	got := make([]uint32, 0, len(groups))
	for _, g := range groups {
		got = append(got, uint32(g))
	}
	if !sameGroups(got, a.Groups) {
		return fmt.Errorf("groups %v, want %v", got, a.Groups)
	}
	return cannotRegain()
}
