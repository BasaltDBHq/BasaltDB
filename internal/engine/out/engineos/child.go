package engineos

import (
	"context"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// childStopWait is how long a child gets after SIGTERM before SIGKILL.
const childStopWait = 30 * time.Second

// StartChild starts exe with args and this process's out and errw, stopped
// with SIGTERM (then SIGKILL after childStopWait) when ctx ends, and taken
// down with this process when it dies (prepareChild). It returns the wait
// for the child's exit.
func StartChild(ctx context.Context, exe string, args []string, out, errw io.Writer) (func() error, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdout, cmd.Stderr = out, errw
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = childStopWait
	prepareChild(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}
