//go:build unix

package web_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// killGroupOnCancel starts cmd in its own process group and, when its
// context ends, kills the whole group rather than the main process alone.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// A browser whose helper process keeps stdout open must not hold the test
// past its timeout: the whole process group is killed and the wait ends.
func TestRunKillableKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "hung-browser")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nsleep 60 &\necho $! > '"+pidFile+"'\nsleep 60\n"), 0o700)) // #nosec G306 -- a test script that must be executable

	start := time.Now()
	_, _, err := runKillable(time.Second, script)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "err = %v", err)
	require.Less(t, time.Since(start), 15*time.Second, "the wait outlasted the timeout")

	b, err := os.ReadFile(pidFile) // #nosec G304 -- the test's own temp file
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 50*time.Millisecond, "the browser's child process %d is still running", pid)
}

// A browser that exits on its own while a helper keeps stdout open must not
// leave the helper running: the wait ends after cmd.WaitDelay and the group
// is killed.
func TestRunKillableKillsHelpersAfterExit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "exiting-browser")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nsleep 60 &\necho $! > '"+pidFile+"'\nexit 0\n"), 0o700)) // #nosec G306 -- a test script that must be executable

	start := time.Now()
	_, _, err := runKillable(30*time.Second, script)
	require.ErrorIs(t, err, exec.ErrWaitDelay)
	require.Less(t, time.Since(start), 20*time.Second)

	b, err := os.ReadFile(pidFile) // #nosec G304 -- the test's own temp file
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 50*time.Millisecond, "the browser's helper %d is still running", pid)
}
