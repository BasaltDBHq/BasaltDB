package cli

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// SleepCtx waits d, or less when ctx ends: false when ctx ended first.
func SleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// HeldAtEveryLook is true when held is true at every one of a few looks,
// sleep apart.
func HeldAtEveryLook(held func() bool, sleep func(time.Duration)) bool {
	const looks, gap = 3, 70 * time.Millisecond
	for i := range looks {
		if !held() {
			return false
		}
		if i < looks-1 {
			sleep(gap)
		}
	}
	return true
}

// ShimExecutable is the path of this binary as a starter runs it: the
// symlink resolved when it can be (a link in ~/.local/bin to a rebuilt
// path), else the path as the OS gave it, which the starter then finds gone.
func ShimExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return ResolveExecutable(exe), nil
}

// ResolveExecutable is exe with its links resolved, else exe as given.
func ResolveExecutable(exe string) string {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// BinaryPath is the absolute path of flagValue, or, when it is empty, of
// this binary with its links resolved.
func BinaryPath(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// InvokingUser is the person running init: under sudo, the user who ran
// sudo, not root.
func InvokingUser() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		return name, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
