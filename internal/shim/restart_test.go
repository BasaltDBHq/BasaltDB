//go:build linux || darwin

package shim_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// dyingEngine accepts one connection, reads n requests, closes it without an
// answer and stops listening: an engine an upgrade restarted mid-call.
func dyingEngine(t *testing.T, socket string, n int) {
	t.Helper()
	takeAndClose(t, socket, n)
}

// engineAfter starts fakeEngine on socket after delay, as a restarted
// service does.
func engineAfter(t *testing.T, socket string, delay time.Duration) {
	t.Helper()
	time.AfterFunc(delay, func() { fakeEngine(t, socket) })
}

func TestAReadTheEngineDroppedInAnUpgradeIsRetriedOnTheNewEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	dyingEngine(t, socket, 1)
	c, done := startShimWaiting(t, socket, 5*time.Second)
	engineAfter(t, socket, 300*time.Millisecond)

	body, isError := c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"], "the new engine answered the same call")

	require.NoError(t, c.in.Close())
	require.NoError(t, <-done)
}

func TestAWriteTheEngineDroppedIsNeverSentAgain(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	dyingEngine(t, socket, 1)
	c, _ := startShimWaiting(t, socket, 5*time.Second)

	start := time.Now()
	body, isError := c.call(t, "write")
	require.Less(t, time.Since(start), 2*time.Second, "answered at once, not held for a retry")
	require.True(t, isError, "%v", body)
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
	require.Contains(t, body["message"], "may or may not have run")
}

func TestACallWaitsForARestartingEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	srv := mcp.NewServer(mcp.Info{Name: "basalt"}, mcp.Tool{
		Name: "write",
		Call: func(context.Context, json.RawMessage) (any, error) { return map[string]string{"from": "first"}, nil },
	})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		answerFirstRequest(srv, conn)
		conn.Close()
		_ = ln.Close()
	}()
	c, _ := startShimWaiting(t, socket, 5*time.Second)
	body, isError := c.call(t, "write")
	require.False(t, isError, "%v", body)
	require.Equal(t, "first", body["from"])

	// The engine restarts: the next call, not yet sent, waits and is served.
	engineAfter(t, socket, 300*time.Millisecond)
	body, isError = c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"])
}

func TestAStoppedEngineIsWaitedForOnce(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	dyingEngine(t, socket, 1)
	c, _ := startShimWaiting(t, socket, 400*time.Millisecond)

	_, isError := c.call(t, "query") // dropped, retried, waited for, unreachable
	require.True(t, isError)
	start := time.Now()
	body, isError := c.call(t, "query")
	require.True(t, isError, "%v", body)
	require.Less(t, time.Since(start), 300*time.Millisecond, "the outage was already waited for")
}

// restartingEngine answers the hello and then every request with "not
// run, restarting" on each connection, closing the listener first, as an
// engine that stops for an upgrade does; it counts the requests it saw.
func restartingEngine(t *testing.T, socket string, seen *int, mu *sync.Mutex) {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = ln.Close()
		defer conn.Close()
		r := bufio.NewReader(conn)
		if _, err := r.ReadBytes('\n'); err != nil {
			return
		}
		_ = mcp.WriteError(conn, mcp.HelloID, -32601, "method not found")
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			req, ok := mcp.RequestOf(line)
			if !ok {
				continue
			}
			mu.Lock()
			*seen++
			mu.Unlock()
			_ = mcp.WriteError(conn, req.ID, mcp.ErrCodeRestarting, mcp.RestartingMessage)
		}
	}()
}

func TestACallTheEngineDidNotRunForARestartIsSentToTheNewEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	var seen int
	var mu sync.Mutex
	restartingEngine(t, socket, &seen, &mu)
	c, _ := startShimWaiting(t, socket, 5*time.Second)
	engineAfter(t, socket, 500*time.Millisecond)

	body, isError := c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"], "the new engine answered the same call")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, seen)
}

func TestACallIsSentAgainForARestartOnlyOnce(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	var seen int
	var mu sync.Mutex
	restartingEngine(t, socket, &seen, &mu)
	c, _ := startShimWaiting(t, socket, 5*time.Second)
	time.AfterFunc(500*time.Millisecond, func() { restartingEngine(t, socket, &seen, &mu) })

	c.id++
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": "tools/call", "params": map[string]any{"name": "write"}})
	require.NoError(t, err)
	_, err = c.in.Write(append(raw, '\n'))
	require.NoError(t, err)
	line, err := c.out.ReadBytes('\n')
	require.NoError(t, err)
	_, restarting := mcp.Restarting(line)
	require.True(t, restarting, "the second engine's answer is passed on: %s", line)
	require.Contains(t, string(line), "Nothing was run")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 2, seen, "sent once more, never a third time")
}
