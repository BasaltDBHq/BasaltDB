//go:build linux

package app

import (
	"os/exec"
	"syscall"
)

// prepareSuperviseChild makes a killed supervisor take its engine with it:
// the kernel sends the child SIGTERM when this process dies. Pdeathsig
// fires when the forking thread exits, not the process; that is fine
// while the supervisor never uses runtime.LockOSThread.
func prepareSuperviseChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
