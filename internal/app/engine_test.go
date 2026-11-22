//go:build linux || darwin

package app_test

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

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/app"
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

func agent(name, dir string, uid uint32) app.Agent {
	return app.Agent{
		Name:       name,
		UID:        uid,
		SocketPath: filepath.Join(dir, name+".sock"),
		Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, whoami(name)),
	}
}

func startEngine(t *testing.T, agents ...app.Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	e := app.New(slog.New(slog.DiscardHandler), agents)
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

// testFallback stands in for what basalt mcp answers while the engine is
// down; a request the engine took and dropped gets an error marked
// "abandoned".
type testFallback struct{ *mcp.Server }

func (testFallback) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	req, ok := mcp.RequestOf(line)
	if !ok {
		return nil
	}
	return mcp.WriteError(out, req.ID, mcp.ErrCodeServer, "abandoned")
}

var fallback = testFallback{mcp.NewServer(mcp.Info{Name: "fallback", Version: "test"}, mcp.Tool{
	Name: "whoami",
	Call: func(context.Context, json.RawMessage) (any, error) {
		return map[string]string{"agent": "the shim"}, nil
	},
})}

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
	require.NoError(t, shim.Serve(ctx, socket, fallback, in, &out))
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

func TestConnectionFromAnotherOSUserIsRefused(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID()+1)
	startEngine(t, bot)

	// The engine answers one refusal line, null id, and runs nothing.
	conn, err := net.Dial("unix", bot.SocketPath)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}` + "\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	msg := mcp.PeerRefusal([]byte(line))
	require.Contains(t, msg, `agent "bot"`, line)
	require.Contains(t, msg, "osUser", "it names who may use the socket")
	require.NotContains(t, line, `"agent": "bot"`, "nothing ran")

	// Through the shim: each request gets that message, never a reset, and
	// basalt mcp ends with it.
	var out strings.Builder
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	err = shim.Serve(rctx, bot.SocketPath, fallback, strings.NewReader(shimRequests), &out)
	require.ErrorContains(t, err, `agent "bot"`)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2, "one answer per request: %s", out.String())
	for _, l := range lines {
		require.Contains(t, l, "osUser")
		require.NotContains(t, l, "may or may not have run")
	}
}

func TestPeerCredentialFailureClosesTheConnection(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := app.New(slog.New(slog.DiscardHandler), []app.Agent{bot}).
		WithPeerUID(func(*net.UnixConn) (uint32, error) { return 0, io.ErrUnexpectedEOF })
	go func() { _ = e.Serve(ctx) }()
	waitListening(t, bot.SocketPath)

	// The engine closes the socket while the shim's request is still
	// unread, so the shim sees a clean end or, depending on timing, a reset
	// (or a broken pipe). Both mean "refused": nothing from the engine may
	// come back. Every request is still answered once, so the client never
	// hangs: one the engine took is answered as abandoned (an error), one the
	// shim could not hand over by its fallback.
	var out strings.Builder
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	err := shim.Serve(rctx, bot.SocketPath, fallback, strings.NewReader(shimRequests), &out)
	if err != nil {
		require.True(t, errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE), "unexpected error: %v", err)
	}
	require.NotContains(t, out.String(), `\"agent\": \"bot\"`)
	require.NotContains(t, out.String(), `"name":"basalt"`)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2, "one answer per request: %s", out.String())
	require.Contains(t, out.String(), `"id":1,`)
	require.Contains(t, out.String(), `"id":2,`)
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
	err = app.New(slog.New(slog.DiscardHandler), []app.Agent{other}).Serve(context.Background())
	require.ErrorContains(t, err, "not a socket")
	raw, err := os.ReadFile(other.SocketPath)
	require.NoError(t, err)
	require.Equal(t, "keep me", string(raw))
}

func TestShimAnswersItselfWithoutAnEngine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	err := shim.Serve(context.Background(), filepath.Join(shortDir(t), "nobody.sock"), fallback, strings.NewReader(shimRequests), &out)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `"name":"fallback"`)
	require.Contains(t, lines[1], `\"agent\": \"the shim\"`)
}

func TestNewPanicsWithoutAgents(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { app.New(slog.New(slog.DiscardHandler), nil) })
	require.Panics(t, func() { app.New(nil, []app.Agent{agent("a", "/tmp", 0)}) })
	require.Panics(t, func() { app.New(slog.New(slog.DiscardHandler), []app.Agent{{Name: "a"}}) })
}

// Refused peers are drained a few at a time per agent; past the cap the
// engine answers and closes at once, and stopping the engine ends the
// drains.
func TestRefusedDrainsAreCapped(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	bot := agent("bot", dir, myUID()+1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := app.New(slog.New(slog.DiscardHandler), []app.Agent{bot}).WithRefusedDrains(2).
		// A long drain window, so no drain times out while the test runs.
		WithRefuseDrain(time.Minute)
	done := make(chan struct{})
	go func() { _ = e.Serve(ctx); close(done) }()
	waitListening(t, bot.SocketPath)

	// refused dials and reads the refusal line, the connection kept open
	// for writing (so the engine drains until EOF).
	refused := func() *net.UnixConn {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: bot.SocketPath, Net: "unix"})
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		r := bufio.NewReader(c)
		require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		require.NotEmpty(t, mcp.PeerRefusal([]byte(line)))
		return c
	}
	// Probes are two bytes each; keep their number far below the engine's
	// 64 KB drain read limit, or it closes the peer on its own.
	// open reports whether the engine still reads c. A write to a socket
	// the peer closed fails at once, so one write tells, with no pacing.
	open := func(c *net.UnixConn) bool {
		_, err := c.Write([]byte("x\n"))
		return err == nil
	}
	// closedWithin polls until c is closed by the engine; it returns false
	// only if that never happens within a generous failure bound.
	closedWithin := func(c *net.UnixConn, bound time.Duration) bool {
		end := time.Now().Add(bound)
		for time.Now().Before(end) {
			if !open(c) {
				return true
			}
			time.Sleep(2 * time.Millisecond)
		}
		return false
	}

	// The engine takes a drain slot after it writes the refusal line, so
	// which of the three connections is closed at once is not fixed; the
	// cap is that exactly one of them is, and the other two stay open.
	conns := []*net.UnixConn{refused(), refused(), refused()}
	closed := -1
	require.Eventually(t, func() bool {
		for i, c := range conns {
			if !open(c) {
				closed = i
				return true
			}
		}
		return false
	}, 10*time.Second, 2*time.Millisecond, "one refused peer is closed at once")
	for i, c := range conns {
		if i != closed {
			require.True(t, open(c), "drained")
		}
	}
	first := conns[(closed+1)%3]

	// Stopping the engine ends the drains well before their minute.
	stopped := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine did not stop")
	}
	require.Less(t, time.Since(stopped), 30*time.Second, "stopping ends the drains, which last a minute")
	require.True(t, closedWithin(first, 5*time.Second), "stopping the engine closes the drained peers")
}
