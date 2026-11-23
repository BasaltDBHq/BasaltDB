//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// testAsBasaltEnv makes the test binary run main() (see TestMain).
const testAsBasaltEnv = "BASALT_TEST_AS_BASALT"

// A supervised engine that is killed comes back by itself: the socket
// answers again within seconds, held by a new process.
func TestSuperviseRealEngineKilled(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", []string{"public.leads"}, nil)
	dir, err := os.MkdirTemp("", "bsup") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "config", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0o700))
	cred := filepath.Join(dir, "config", "product_a.url")
	require.NoError(t, os.WriteFile(cred, []byte(a.URL+"\n"), config.FileMode))
	me, err := user.Current()
	require.NoError(t, err)
	socketDir := filepath.Join(dir, "run")
	raw, err := json.Marshal(map[string]any{
		"socketDir": socketDir, "stateDir": filepath.Join(dir, "state"), "pagesAddr": "off", "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "product_a", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))

	exe, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	sup := exec.CommandContext(ctx, exe, "engine", "--supervise", "--config", cfgPath)
	sup.Env = append(os.Environ(), testAsBasaltEnv+"=1")
	sup.Cancel = func() error { return sup.Process.Signal(syscall.SIGTERM) }
	require.NoError(t, sup.Start())
	t.Cleanup(func() {
		cancel()
		_ = sup.Wait()
	})
	sock := config.SocketPath(socketDir, "product_a")
	enginePID := func() int {
		pid, up, _ := pidlock.Running(engine.LockPath(socketDir))
		if !up {
			return 0
		}
		return pid
	}
	answers := func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	var first int
	require.Eventually(t, func() bool { first = enginePID(); return first > 0 && answers() }, 30*time.Second, 50*time.Millisecond)

	require.Equal(t, "HAND", engineStartedBy(t, sock), "run by hand under --supervise, with no --started-by")
	require.NoError(t, syscall.Kill(first, syscall.SIGKILL))

	require.Eventually(t, func() bool {
		pid := enginePID()
		return pid > 0 && pid != first && answers()
	}, 5*time.Second, 50*time.Millisecond, "the supervisor starts the engine again")
	require.Equal(t, "CRASH", engineStartedBy(t, sock), "the supervisor's restart says so")
}

// engineStartedBy is status.engine.startedBy as an MCP client on the agent's
// socket reads it.
func engineStartedBy(t *testing.T, sock string) string {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(t, resp.Result.Content, 1, line)
	var report struct {
		Engine struct {
			StartedBy string `json:"startedBy"`
		} `json:"engine"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &report))
	return report.Engine.StartedBy
}

// A basalt mcp that finds no engine starts one under a supervisor, waits
// for it and answers status through it: no step by anyone.
func TestMCPStartsDownEngine(t *testing.T) {
	t.Setenv(testAsBasaltEnv, "1") // the engine it starts is this test binary
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", []string{"public.leads"}, nil)
	dir, err := os.MkdirTemp("", "bmcp") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "config", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0o700))
	cred := filepath.Join(dir, "config", "product_a.url")
	require.NoError(t, os.WriteFile(cred, []byte(a.URL+"\n"), config.FileMode))
	me, err := user.Current()
	require.NoError(t, err)
	socketDir := filepath.Join(dir, "run")
	raw, err := json.Marshal(map[string]any{
		"socketDir": socketDir, "stateDir": filepath.Join(dir, "state"), "pagesAddr": "off", "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "product_a", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))
	t.Cleanup(func() { // the engine is detached: stop its supervisor
		if pid, up, _ := pidlock.Running(engine.LockPath(socketDir)); up {
			if ppid, err := parentOf(pid); err == nil {
				_ = syscall.Kill(ppid, syscall.SIGTERM)
			}
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	})
	_, up, _ := pidlock.Running(engine.LockPath(socketDir))
	require.False(t, up, "no engine runs before the call")

	in, inW := io.Pipe()
	var out bytes.Buffer
	outR, outW := io.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- enginecli.RunMCPAt(context.Background(), []string{"--agent", "product_a"}, cli.Stdio{In: in, Out: outW, Err: &out}, osHost{}, engineCLIHost{}, cfgPath)
		_ = outW.Close()
	}()
	_, err = fmt.Fprintf(inW, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(outR)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(t, resp.Result.Content, 1, line)
	var report struct {
		Problems []struct {
			Code     string `json:"code"`
			Severity string `json:"severity"`
		} `json:"problems"`
		Engine struct {
			Reachable bool   `json:"reachable"`
			StartedBy string `json:"startedBy"`
		} `json:"engine"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &report))
	require.True(t, report.Engine.Reachable, resp.Result.Content[0].Text)
	for _, p := range report.Problems {
		if p.Severity == "ERROR" {
			require.Equal(t, "NO_PASSKEY", p.Code, "ready but for the passkey the test database has none of: %s", resp.Result.Content[0].Text)
		}
	}
	require.Equal(t, "MCP", report.Engine.StartedBy, "basalt mcp started this engine")

	pid, up, _ := pidlock.Running(engine.LockPath(socketDir))
	require.True(t, up)
	ppid, err := parentOf(pid)
	require.NoError(t, err)
	cmdline, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(ppid)).Output()
	require.NoError(t, err)
	require.Contains(t, string(cmdline), "--supervise", "the engine runs under a supervisor")
	_, err = os.Stat(filepath.Join(dir, "state", engineLogName))
	require.NoError(t, err, "its output goes to the engine log")

	require.NoError(t, inW.Close())
	require.Equal(t, cli.ExitOK, <-done, out.String())
}

func parentOf(pid int) (int, error) {
	b, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// An engine started by hand holds the engine lock: the supervisor's child
// fails at once, and the supervisor ends with 0 instead of crash-looping.
func TestSuperviseBesideAnEngineStartedByHand(t *testing.T) {
	t.Setenv(testAsBasaltEnv, "1")       // the child is this test binary
	dir, err := os.MkdirTemp("", "bsup") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "engine.json")
	raw := `{"socketDir":"` + filepath.Join(dir, "run") + `","stateDir":"` + filepath.Join(dir, "state") + `","mode":"SAME_USER",` +
		`"agents":[{"name":"bot","osUser":"someone","store":{"kind":"POSTGRES","credentialFile":"` + filepath.Join(dir, "bot.url") + `"}}]}`
	require.NoError(t, config.WriteFile(cfgPath, []byte(raw)))
	hand, err := pidlock.AcquireLock(engine.LockPath(filepath.Join(dir, "run")))
	require.NoError(t, err)
	defer hand.Release()
	var stderr bytes.Buffer

	code := runSupervise(context.Background(), cfgPath, startedByHand, cli.Stdio{In: bytes.NewReader(nil), Out: &bytes.Buffer{}, Err: &stderr}, osHost{})

	require.Equal(t, cli.ExitOK, code, stderr.String())
	require.Contains(t, stderr.String(), "another engine already runs for this config")
	require.NotContains(t, stderr.String(), "restarting it", "no crash loop")
}
