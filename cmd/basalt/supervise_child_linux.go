//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// prepareSuperviseChild makes a killed supervisor take its engine with it:
// the kernel sends the child SIGTERM when this process dies.
func prepareSuperviseChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
