//go:build linux || darwin

package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// silentDatabase accepts TCP connections and never answers on them: a
// database that is slow or drops packets after the connect.
func silentDatabase(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// The engine binds the agent's socket before it reads the agent's
// database: a database that never answers does not keep the socket down.
func TestRunServesBeforeTheDatabaseAnswers(t *testing.T) {
	t.Parallel()
	addr := silentDatabase(t)
	dir, err := os.MkdirTemp("", "bslow") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketDir, stateDir := filepath.Join(dir, "run"), filepath.Join(dir, "state")
	cfgPath := filepath.Join(dir, "config", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0o700))
	cred := filepath.Join(dir, "config", "product_a.url")
	url := "postgres://basalt_agent_product_a:pw@" + addr + "/app?sslmode=disable"
	require.NoError(t, os.WriteFile(cred, []byte(url+"\n"), config.FileMode))
	me, err := user.Current()
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{
		"socketDir": socketDir, "stateDir": stateDir, "pagesAddr": "off", "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "product_a", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	sock := config.SocketPath(socketDir, "product_a")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWith(ctx, cfg, cfgPath, slog.New(slog.DiscardHandler), restartOptions{})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "the socket serves while the database has not answered")
}
