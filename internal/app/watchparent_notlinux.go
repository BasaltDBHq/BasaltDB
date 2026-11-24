//go:build unix && !linux

package app

import (
	"context"
	"os"
	"strconv"
	"syscall"
)

func watchSupervisedParent(ctx context.Context) {
	want, err := strconv.Atoi(os.Getenv(watchParentEnv))
	if err != nil || want <= 1 {
		return
	}
	stop := func() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) }
	if os.Getppid() != want {
		// The supervisor is already gone (parent is pid 1 or another reaper).
		stop()
		return
	}
	watchParent(ctx, want, stop)
}
