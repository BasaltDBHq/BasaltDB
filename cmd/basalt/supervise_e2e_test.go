//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/server"
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
		pid, up, _ := server.Running(engine.LockPath(socketDir))
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

	require.NoError(t, syscall.Kill(first, syscall.SIGKILL))

	require.Eventually(t, func() bool {
		pid := enginePID()
		return pid > 0 && pid != first && answers()
	}, 5*time.Second, 50*time.Millisecond, "the supervisor starts the engine again")
}
