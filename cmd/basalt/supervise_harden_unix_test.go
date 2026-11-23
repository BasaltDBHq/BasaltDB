//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

const (
	testSuperviseRoleEnv    = "BASALT_TEST_SUPERVISE_ROLE"
	testSupervisePidFileEnv = "BASALT_TEST_SUPERVISE_PIDFILE"
)

// A supervisor that is killed takes its engine with it, so the next
// start can launch a fresh supervisor.
func TestSupervisedChildStopsWhenParentIsKilled(t *testing.T) {
	switch os.Getenv(testSuperviseRoleEnv) {
	case "child":
		watchSupervisedParent(context.Background())
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedChildStopsWhenParentIsKilled$")
		cmd.Env = append(cleanTestEnv(), testSuperviseRoleEnv+"=child")
		prepareSuperviseChild(cmd)
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		if err := os.WriteFile(os.Getenv(testSupervisePidFileEnv), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
			_ = cmd.Process.Kill()
			os.Exit(1)
		}
		_, _ = os.Stdin.Read(make([]byte, 1))
		os.Exit(0)
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestSupervisedChildStopsWhenParentIsKilled$")
	parent.Env = append(cleanTestEnv(), testSuperviseRoleEnv+"=parent", testSupervisePidFileEnv+"="+pidFile)
	parent.Stdout, parent.Stderr = io.Discard, io.Discard
	stdin, err := parent.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, parent.Start())
	t.Cleanup(func() { _ = stdin.Close() })
	t.Cleanup(func() {
		if parent.Process != nil {
			_ = parent.Process.Kill()
			_ = parent.Wait()
		}
	})
	var childPid int
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		childPid, err = strconv.Atoi(string(raw))
		return err == nil && childPid > 0 && processAlive(childPid)
	}, 5*time.Second, 20*time.Millisecond)

	require.NoError(t, parent.Process.Kill()) // SIGKILL, as kill -9 of a supervisor would
	_ = parent.Wait()

	require.Eventually(t, func() bool { return !processAlive(childPid) }, 5*time.Second, 50*time.Millisecond, "the child must stop within a few seconds of its supervisor")
}

func cleanTestEnv() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, testAsBasaltEnv+"=") || strings.HasPrefix(e, testSuperviseRoleEnv+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func TestWatchParentKillsOnceTheParentIsGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := parentGonePoll
	parentGonePoll = 20 * time.Millisecond
	t.Cleanup(func() { parentGonePoll = old })

	var called atomic.Int32
	watchParent(ctx, os.Getppid(), func() { called.Add(1) })
	time.Sleep(80 * time.Millisecond)
	require.EqualValues(t, 0, called.Load(), "a living parent is not a stop")

	watchParent(ctx, os.Getppid()+100000, func() { called.Add(1) })
	require.Eventually(t, func() bool { return called.Load() == 1 }, time.Second, 10*time.Millisecond)
}

// A supervisor started from a copy of the binary records the missing path
// in last-stop.json and stops when that copy is removed after a crash.
func TestSuperviseStopsWhenStartedFromPathIsGone(t *testing.T) {
	dir, err := os.MkdirTemp("", "bgone")
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	self, err := os.Executable()
	require.NoError(t, err)
	bin := filepath.Join(dir, "basalt")
	copyFile(t, self, bin)
	cfgPath := filepath.Join(dir, "engine.json")
	socketDir := filepath.Join(dir, "run")
	stateDir := filepath.Join(dir, "state")
	raw, err := json.Marshal(map[string]any{
		"socketDir": socketDir, "stateDir": stateDir, "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "bot", "osUser": "someone", "store": map[string]any{"kind": "POSTGRES", "credentialFile": filepath.Join(dir, "bot.url")}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))

	cmd := exec.Command(bin, "engine", "--supervise", "--config", cfgPath)
	cmd.Env = append(cleanTestEnv(), testAsBasaltEnv+"=1")
	cmd.Dir = dir
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	require.Eventually(t, func() bool {
		held, err := lockHeld(filepath.Join(socketDir, superviseLock))
		return err == nil && held
	}, 5*time.Second, 20*time.Millisecond)
	if pid, up, _ := pidlock.Running(engine.LockPath(socketDir)); up {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	require.NoError(t, os.Remove(bin))

	require.Eventually(t, func() bool {
		stop, ok := agent.ReadLastStop(stateDir)
		return ok && strings.Contains(stop.Reason, "is gone") && strings.Contains(stop.Reason, bin)
	}, 8*time.Second, 50*time.Millisecond)
	err = cmd.Wait()
	require.Error(t, err, "the supervisor exits 1 when the binary is gone")
	held, err := lockHeld(filepath.Join(socketDir, superviseLock))
	require.NoError(t, err)
	require.False(t, held, "the next basalt mcp call can start a fresh supervisor")
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()
	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

// The supervisor can die between forking the child and the child's first
// look at its parent: the child must still stop, not watch pid 1.
func TestSupervisedChildStopsWhenSupervisorIsAlreadyGone(t *testing.T) {
	if os.Getenv(testSuperviseRoleEnv) == "orphan" {
		watchSupervisedParent(context.Background())
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if runtime.GOOS == "linux" {
		t.Skip("Linux uses Pdeathsig; there is no parent watcher")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisedChildStopsWhenSupervisorIsAlreadyGone$")
	// BASALT_SUPERVISED names a pid that is not this child's parent.
	cmd.Env = append(cleanTestEnv(), testSuperviseRoleEnv+"=orphan", "BASALT_SUPERVISED="+strconv.Itoa(os.Getpid()+1000))
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the child kept running although its parent is not the supervisor named in the environment")
	}
}
