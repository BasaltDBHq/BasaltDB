//go:build linux || darwin

package app

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// olderGuard is a same-user engine setup for agent bot: its database, its
// engine config and its credential file, in a socket directory short
// enough for macOS.
type olderGuard struct {
	d          *guardtest.DB
	configPath string
	socketDir  string
}

// startEngine runs the engine in this process on g's config until the test
// ends, as the person runs it in the foreground.
func (g olderGuard) startEngine(t *testing.T) {
	t.Helper()
	cfg, err := config.Load(g.configPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWith(ctx, cfg, g.configPath, slog.New(slog.DiscardHandler), restartOptions{})
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	sock := config.SocketPath(g.socketDir, "bot")
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 10*time.Second, 20*time.Millisecond)
}

// callTool calls tool on the running engine's socket for bot, as the
// agent's MCP client does, and returns the tools/call response line.
func (g olderGuard) callTool(t *testing.T, tool string) string {
	t.Helper()
	conn, err := net.Dial("unix", config.SocketPath(g.socketDir, "bot"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	return line
}
