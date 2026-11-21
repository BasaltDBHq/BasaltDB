//go:build unix

package main

import (
	"context"
	"os"
	"time"
)

// parentGonePoll is how often a supervised child looks at its parent; a
// killed supervisor's engine must stop within a few seconds.
var parentGonePoll = time.Second

// watchParent calls kill once getppid is no longer ppid (the parent died
// and this process was reparented). A ppid of 1 means there is no
// supervisor to watch.
func watchParent(ctx context.Context, ppid int, kill func()) {
	if ppid <= 1 || kill == nil {
		return
	}
	go func() {
		t := time.NewTicker(parentGonePoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if os.Getppid() != ppid {
					kill()
					return
				}
			}
		}
	}()
}
