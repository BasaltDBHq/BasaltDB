//go:build unix

package child

import (
	"bytes"
	"encoding/json"
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

const peerFlag = "--child-test-peer"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == peerFlag {
		peerMain(os.Args[2:])
	}
	os.Exit(m.Run())
}

// peerReport is what the "report" peer prints.
type peerReport struct {
	Env []string `json:"env"`
	Dir string   `json:"dir"`
}

// peerMain: "report" prints its environment and working directory;
// "grandchild FILE" starts a "sleep" peer, writes its pid to FILE and
// sleeps; "sleep" sleeps.
func peerMain(args []string) {
	switch args[0] {
	case "report":
		dir, _ := os.Getwd()
		b, err := json.Marshal(peerReport{Env: os.Environ(), Dir: dir})
		if err != nil {
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(b)
		os.Exit(0)
	case "engine":
		fakeEngine(args[1], args[2], args[3], args[4])
	case "grandchild":
		gc := exec.Command(os.Args[0], peerFlag, "sleep")
		if gc.Start() != nil {
			os.Exit(1)
		}
		if os.WriteFile(args[1], []byte(strconv.Itoa(gc.Process.Pid)), 0o600) != nil {
			os.Exit(1)
		}
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}

// The child gets only the environment it is given (none by default) and
// runs in its directory, not the caller's.
func TestEnvironmentAndDirectory(t *testing.T) {
	t.Setenv("BASALT_TEST_SECRET", "must-not-reach-the-plugin")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, env := range [][]string{nil, {"BASALT_PLUGIN_SOCKET=/s/p.sock"}} {
		var out bytes.Buffer
		p, err := Start(Spec{Path: os.Args[0], Args: []string{peerFlag, "report"}, Dir: dir, Env: env, Stdout: &out})
		require.NoError(t, err)
		<-p.Exited()
		p.Stop()
		var r peerReport
		require.NoError(t, json.Unmarshal(out.Bytes(), &r), out.String())
		require.Equal(t, env, nilIfEmpty(r.Env))
		got, err := filepath.EvalSymlinks(r.Dir)
		require.NoError(t, err)
		require.Equal(t, dir, got)
	}
	_, err = Start(Spec{Path: os.Args[0]})
	require.ErrorIs(t, err, ErrNoDir)
}

// gone reports whether pid no longer runs: it does not exist, or it is a
// zombie its new parent has not reaped yet.
func gone(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Stop kills the whole process group: a process the plugin started is
// gone too.
func TestStopKillsTheGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	p, err := Start(Spec{Path: os.Args[0], Args: []string{peerFlag, "grandchild", pidFile}, Dir: t.TempDir()})
	require.NoError(t, err)
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil || len(b) == 0 {
			return false
		}
		pid, err = strconv.Atoi(string(b))
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, syscall.Kill(pid, 0), "the grandchild runs")

	p.Stop()
	select {
	case <-p.Exited():
	default:
		t.Fatal("the child was not reaped")
	}
	require.Eventually(t, func() bool { return gone(pid) }, 10*time.Second, 10*time.Millisecond, "the grandchild was killed with its group")
	p.Stop() // again: a no-op
}
