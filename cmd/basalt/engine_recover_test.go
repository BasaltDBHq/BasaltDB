//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// recoverRig is a same-user engine config on a real guard, not yet running.
type recoverRig struct {
	t                   *testing.T
	cfgPath, cred       string
	socketDir, stateDir string
	sock                string
	cfg                 config.Config
	cancel              context.CancelFunc
	done                chan error
}

func newRecoverRig(t *testing.T) *recoverRig {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", []string{"public.leads"}, nil)
	dir, err := os.MkdirTemp("", "brec") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	r := &recoverRig{t: t, socketDir: filepath.Join(dir, "run"), stateDir: filepath.Join(dir, "state")}
	r.cfgPath = filepath.Join(dir, "config", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(r.cfgPath), 0o700))
	r.cred = filepath.Join(dir, "config", "product_a.url")
	require.NoError(t, os.WriteFile(r.cred, []byte(a.URL+"\n"), config.FileMode))
	me, err := user.Current()
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{
		"socketDir": r.socketDir, "stateDir": r.stateDir, "pagesAddr": "off", "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "product_a", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": r.cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(r.cfgPath, raw))
	r.cfg, err = config.Load(r.cfgPath)
	require.NoError(t, err)
	r.sock = config.SocketPath(r.socketDir, "product_a")
	return r
}

// start runs the engine in this process until the test ends.
func (r *recoverRig) start(startedBy string) {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan error, 1)
	go func() {
		r.done <- engine.RunWith(ctx, r.cfg, r.cfgPath, slog.New(slog.DiscardHandler), engine.RestartOptions{StartedBy: startedBy})
	}()
	r.t.Cleanup(func() { cancel() })
}

func (r *recoverRig) answers() bool {
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return fi.Mode().Perm()
}

// An update of the computer leaves 0755 folders, drops the empty run
// folder and leaves a lock file with a dead pid and a socket nothing
// answers on: the engine starts anyway and leaves its folders 0700.
func TestRunAfterUpdateLikeRestore(t *testing.T) {
	t.Parallel()
	r := newRecoverRig(t)
	// The state directory exists at 0755 with a key file in it; the run
	// directory was dropped, but a lock file and a socket survive in a
	// recreated, 0755 one.
	require.NoError(t, os.MkdirAll(r.stateDir, 0o755))
	require.NoError(t, os.Chmod(r.stateDir, 0o755))
	require.NoError(t, os.MkdirAll(r.socketDir, 0o755))
	require.NoError(t, os.Chmod(r.socketDir, 0o755))
	require.NoError(t, os.WriteFile(engine.LockPath(r.socketDir), []byte("999999\n"), 0o644))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: r.sock, Net: "unix"})
	require.NoError(t, err)
	ln.SetUnlinkOnClose(false)
	require.NoError(t, ln.Close()) // the file stays, as after a kill
	_, err = os.Lstat(r.sock)
	require.NoError(t, err)

	r.start("mcp")

	require.Eventually(t, r.answers, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, os.FileMode(0o700), permOf(t, r.stateDir))
	require.Equal(t, os.FileMode(0o700), permOf(t, r.socketDir))
}

// Folders that are gone are made.
func TestRunAfterFoldersAreDeleted(t *testing.T) {
	t.Parallel()
	r := newRecoverRig(t)
	for _, d := range []string{r.socketDir, r.stateDir} {
		_, err := os.Stat(d)
		require.ErrorIs(t, err, os.ErrNotExist)
	}

	r.start("hand")

	require.Eventually(t, r.answers, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, os.FileMode(0o700), permOf(t, r.stateDir))
	require.Equal(t, os.FileMode(0o700), permOf(t, r.socketDir))
}

// A credential file that is not 0600 is still refused, and never fixed.
func TestRunRefusesLooseCredential(t *testing.T) {
	t.Parallel()
	r := newRecoverRig(t)
	require.NoError(t, os.Chmod(r.cred, 0o644))

	r.start("hand")

	select {
	case err := <-r.done:
		require.Error(t, err)
		require.Contains(t, err.Error(), "0600")
	case <-time.After(30 * time.Second):
		t.Fatal("the engine served with a credential file that is not 0600")
	}
	require.Equal(t, os.FileMode(0o644), permOf(t, r.cred), "the file is not changed")
	require.False(t, r.answers())
}
