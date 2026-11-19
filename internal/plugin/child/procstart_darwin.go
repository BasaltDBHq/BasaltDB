package child

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// procStart is pid's start-time identity: its start time to the
// microsecond, from the kernel's process table.
func procStart(pid int) (string, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp.Proc.P_pid != int32(pid) {
		return "", errNoStart
	}
	t := kp.Proc.P_starttime
	if t.Sec == 0 && t.Usec == 0 {
		return "", errNoStart
	}
	return fmt.Sprintf("%d.%06d", t.Sec, t.Usec), nil
}
