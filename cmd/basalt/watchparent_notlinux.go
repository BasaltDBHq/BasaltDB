//go:build unix && !linux

package main

import (
	"context"
	"os"
	"syscall"
)

// watchSupervisedParent stops this engine when its supervisor is gone
// (Linux already does this with Pdeathsig).
func watchSupervisedParent(ctx context.Context) {
	if os.Getenv(watchParentEnv) == "" {
		return
	}
	watchParent(ctx, os.Getppid(), func() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) })
}
