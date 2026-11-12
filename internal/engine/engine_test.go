//go:build linux || darwin

package engine_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

// shortDir is a socket directory short enough for macOS's ~104-byte Unix
// socket path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "beng")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func whoami(name string) mcp.Tool {
	return mcp.Tool{Name: "whoami", Call: func(context.Context, json.RawMessage) (any, error) {
		return map[string]string{"agent": name}, nil
	}}
}

func agent(name, dir string, uid uint32) engine.Agent {
	return engine.Agent{
		Name:       name,
		UID:        uid,
		SocketPath: filepath.Join(dir, name+".sock"),
		Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, whoami(name)),
	}
}

func startEngine(t *testing.T, agents ...engine.Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	e := engine.New(slog.New(slog.DiscardHandler), agents)
	go func() { done <- e.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
		for _, a := range agents {
			_, err := os.Lstat(a.SocketPath)
			require.ErrorIs(t, err, os.ErrNotExist, "socket removed on shutdown")
		}
	})
	for _, a := range agents {
		waitListening(t, a.SocketPath)
	}
}

func waitListening(t *testing.T, path string) {
	t.Helper()
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", path)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
}

func myUID() uint32 {
	return uint32(os.Getuid())
}

// shimRequests is an initialize and a tools/call, one per line.
const shimRequests = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
	`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami"}}` + "\n"

// callThroughShim runs one initialize and one tools/call through the shim,
// as an agent's MCP client would over stdio.
func callThroughShim(t *testing.T, socket string) string {
	t.Helper()
	in := strings.NewReader(shimRequests)
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, shim.Relay(ctx, socket, in, &out))
	return out.String()
}

func TestShimRelaysToTheAgentsSocket(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot, other := agent("bot", dir, myUID()), agent("other", dir, myUID())
	startEngine(t, bot, other)

	fi, err := os.Stat(bot.SocketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o666), fi.Mode().Perm())

	out := callThroughShim(t, bot.SocketPath)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `"serverInfo"`)
	require.Contains(t, lines[1], `\"agent\": \"bot\"`)

	require.Contains(t, callThroughShim(t, other.SocketPath), `\"agent\": \"other\"`)
}

func TestConnectionFromAnotherOSUserIsClosed(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID()+1)
	startEngine(t, bot)

	conn, err := net.Dial("unix", bot.SocketPath)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}` + "\n"))
	if err == nil {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err = bufio.NewReader(conn).ReadString('\n')
	}
	require.Error(t, err, "the engine must close the connection without answering")
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestPeerCredentialFailureClosesTheConnection(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := engine.New(slog.New(slog.DiscardHandler), []engine.Agent{bot}).
		WithPeerUID(func(*net.UnixConn) (uint32, error) { return 0, io.ErrUnexpectedEOF })
	go func() { _ = e.Serve(ctx) }()
	waitListening(t, bot.SocketPath)

	// The engine closes the socket while the shim's request is still
	// unread, so the shim sees a clean end or, depending on timing, a reset
	// (or a broken pipe). Both mean "refused"; nothing may come back. The
	// shim itself must keep reporting a reset mid-response as an error.
	var out strings.Builder
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	err := shim.Relay(rctx, bot.SocketPath, strings.NewReader(shimRequests), &out)
	if err != nil {
		require.True(t, errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE), "unexpected error: %v", err)
	}
	require.Empty(t, out.String())
}

func TestStaleSocketIsReplacedButOtherFilesAreNot(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID())

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: bot.SocketPath, Net: "unix"})
	require.NoError(t, err)
	stale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	startEngine(t, bot)
	require.Contains(t, callThroughShim(t, bot.SocketPath), `\"agent\": \"bot\"`)

	other := agent("other", dir, myUID())
	require.NoError(t, os.WriteFile(other.SocketPath, []byte("keep me"), 0o600))
	err = engine.New(slog.New(slog.DiscardHandler), []engine.Agent{other}).Serve(context.Background())
	require.ErrorContains(t, err, "not a socket")
	raw, err := os.ReadFile(other.SocketPath)
	require.NoError(t, err)
	require.Equal(t, "keep me", string(raw))
}

func TestShimReportsAMissingEngine(t *testing.T) {
	t.Parallel()
	err := shim.Relay(context.Background(), filepath.Join(shortDir(t), "nobody.sock"), strings.NewReader(""), io.Discard)
	require.ErrorContains(t, err, "is the engine service running?")
}

func TestNewPanicsWithoutAgents(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { engine.New(slog.New(slog.DiscardHandler), nil) })
	require.Panics(t, func() { engine.New(nil, []engine.Agent{agent("a", "/tmp", 0)}) })
	require.Panics(t, func() { engine.New(slog.New(slog.DiscardHandler), []engine.Agent{{Name: "a"}}) })
}
