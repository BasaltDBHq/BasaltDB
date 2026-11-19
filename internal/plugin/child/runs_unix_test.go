//go:build unix

package child

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shortDir is a new directory under TMPDIR short enough for a socket path.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// leaveSocket makes a socket file at path that stays when its listener is
// closed, as a killed plugin leaves it.
func leaveSocket(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, l.Close())
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.ModeSocket, fi.Mode().Type())
}

func readPID(t *testing.T, file string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(file)
		if err != nil || len(b) == 0 {
			return false
		}
		pid, err = strconv.Atoi(string(b))
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	return pid
}

// fakeEngine runs as the "engine" peer: it starts a "grandchild" plugin
// with a run record and its socket directory, writes the plugin's pid and
// waits to be killed.
func fakeEngine(runsDir, socketDir, pluginPID, grandchildPID string) {
	p, err := Start(Spec{
		Path: os.Args[0], Args: []string{peerFlag, "grandchild", grandchildPID}, Dir: "/",
		Runs: &Runs{Dir: runsDir}, SocketDir: socketDir,
	})
	if err != nil {
		os.Exit(1)
	}
	if os.WriteFile(pluginPID, []byte(strconv.Itoa(p.cmd.Process.Pid)), 0o600) != nil {
		os.Exit(1)
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}

// After the engine is killed with SIGKILL, its plugin and what the plugin
// started run on and the socket directory stays; the next start's Reap
// kills that process group, removes the socket directory and drops the
// record.
func TestReapAfterEngineKilled(t *testing.T) {
	base := shortDir(t)
	runs := filepath.Join(base, "runs")
	sockDir := filepath.Join(base, "bp1")
	require.NoError(t, os.Mkdir(sockDir, 0o700))
	leaveSocket(t, filepath.Join(sockDir, socketName))
	pluginFile, gcFile := filepath.Join(base, "plugin.pid"), filepath.Join(base, "gc.pid")

	engine := exec.Command(os.Args[0], peerFlag, "engine", runs, sockDir, pluginFile, gcFile)
	require.NoError(t, engine.Start())
	pid, gc := readPID(t, pluginFile), readPID(t, gcFile)
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	require.NoError(t, engine.Process.Signal(syscall.SIGKILL))
	_ = engine.Wait()

	time.Sleep(100 * time.Millisecond)
	require.False(t, gone(pid), "the plugin outlived the killed engine")
	require.False(t, gone(gc), "so did what it started")
	recs, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Len(t, recs, 1, "the record the killed engine left")

	Reap(runs, nil)
	require.Eventually(t, func() bool { return gone(pid) && gone(gc) }, 10*time.Second, 10*time.Millisecond, "the earlier plugin's group is stopped")
	_, err = os.Lstat(sockDir)
	require.ErrorIs(t, err, os.ErrNotExist, "its socket directory is removed")
	recs, err = os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, recs)
}

// A started process is recorded until Stop, which removes the record.
func TestRecordLastsUntilStop(t *testing.T) {
	runs := filepath.Join(shortDir(t), "runs")
	p, err := Start(Spec{Path: os.Args[0], Args: []string{peerFlag, "sleep"}, Dir: "/", Runs: &Runs{Dir: runs}})
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(runs, strconv.Itoa(p.cmd.Process.Pid)+recordSuffix))
	require.NoError(t, err)
	var rec record
	require.NoError(t, json.Unmarshal(b, &rec))
	start, err := procStart(rec.PID)
	require.NoError(t, err)
	require.Equal(t, start, rec.Start)
	fi, err := os.Stat(runs)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	p.Stop()
	recs, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, recs)
}

// A recorded pid that now runs another process (its start time differs) is
// not killed; its record is dropped.
func TestReapSparesAnotherProcess(t *testing.T) {
	runs := filepath.Join(shortDir(t), "runs")
	require.NoError(t, os.Mkdir(runs, 0o700))
	other := exec.Command(os.Args[0], peerFlag, "sleep")
	other.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, other.Start())
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	_, err := (&Runs{Dir: runs}).write(record{PID: other.Process.Pid, Start: "not-its-start"})
	require.NoError(t, err)

	Reap(runs, nil)
	time.Sleep(50 * time.Millisecond)
	require.False(t, gone(other.Process.Pid), "a process that is not the recorded one is spared")
	recs, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, recs)
}

// pid 0, 1, the engine's own pid and its own group are never killed, even
// when the start time matches; a malformed record is dropped untouched.
func TestReapNeverKillsTheEngineOrInit(t *testing.T) {
	var killed []int
	reapStart = func(int) (string, error) { return "s", nil }
	reapKill = func(pid int) error { killed = append(killed, pid); return nil }
	t.Cleanup(func() { reapStart, reapKill = procStart, killGroupID })

	runs := filepath.Join(shortDir(t), "runs")
	r := &Runs{Dir: runs}
	for _, pid := range []int{0, 1, os.Getpid(), syscall.Getpgrp(), 4242} {
		_, err := r.write(record{PID: pid, Start: "s"})
		require.NoError(t, err)
	}
	require.NoError(t, os.WriteFile(filepath.Join(runs, "7.json"), []byte("{not json"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runs, "8.json"), []byte(`{"pid":8}`), 0o600))
	Reap(runs, nil)
	require.Equal(t, []int{4242}, killed)
	recs, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, recs)
}

// A recorded socket directory is removed only when it is the engine's user's
// own directory holding nothing but its socket.
func TestReapKeepsAnythingButAnEmptySocketDir(t *testing.T) {
	reapStart = func(int) (string, error) { return "", errNoStart }
	t.Cleanup(func() { reapStart = procStart })
	base := shortDir(t)
	runs := filepath.Join(base, "runs")
	r := &Runs{Dir: runs}

	extra := filepath.Join(base, "extra")
	require.NoError(t, os.Mkdir(extra, 0o700))
	leaveSocket(t, filepath.Join(extra, socketName))
	require.NoError(t, os.WriteFile(filepath.Join(extra, "keep"), []byte("x"), 0o600))

	notSock := filepath.Join(base, "notsock")
	require.NoError(t, os.Mkdir(notSock, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(notSock, socketName), []byte("x"), 0o600))

	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(target, link))

	empty := filepath.Join(base, "empty")
	require.NoError(t, os.Mkdir(empty, 0o700))

	for i, d := range []string{extra, notSock, link, empty, "relative/dir"} {
		_, err := r.write(record{PID: 100000 + i, Start: "s", SocketDir: d})
		require.NoError(t, err)
	}
	Reap(runs, nil)
	for _, d := range []string{extra, filepath.Join(extra, "keep"), filepath.Join(extra, socketName), notSock, link, target} {
		_, err := os.Lstat(d)
		require.NoError(t, err, "%s kept", d)
	}
	_, err := os.Lstat(empty)
	require.ErrorIs(t, err, os.ErrNotExist, "an empty socket directory is removed")
}

// A runs directory that is a symlink is not read.
func TestReapIgnoresASymlinkedRunsDir(t *testing.T) {
	base := shortDir(t)
	target := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "9.json"), []byte(`{"pid":9,"start":"s"}`), 0o600))
	link := filepath.Join(base, "runs")
	require.NoError(t, os.Symlink(target, link))
	Reap(link, nil)
	_, err := os.Lstat(filepath.Join(target, "9.json"))
	require.NoError(t, err, "nothing read or removed through the symlink")
}
