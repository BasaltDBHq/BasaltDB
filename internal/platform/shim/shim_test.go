//go:build linux || darwin

package shim_test

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
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// client is an MCP client on the shim's stdio: one request, one answer.
type client struct {
	in  *io.PipeWriter
	out *bufio.Reader
	id  int
}

func (c *client) request(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	c.id++
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	require.NoError(t, err)
	_, err = c.in.Write(append(raw, '\n'))
	require.NoError(t, err)
	line, err := c.out.ReadBytes('\n')
	require.NoError(t, err)
	var resp struct {
		ID     int            `json:"id"`
		Result map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(line, &resp), string(line))
	require.Equal(t, c.id, resp.ID)
	return resp.Result
}

// call runs tools/call and returns the decoded body and isError.
func (c *client) call(t *testing.T, tool string) (map[string]any, bool) {
	t.Helper()
	res := c.request(t, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{}})
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &body), text)
	return body, res["isError"].(bool)
}

func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bshim") // short: Unix socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startShim runs basalt mcp's relay for socket with the engine-down
// fallback, as the agent's MCP client would start it.
func startShim(t *testing.T, socket string) (*client, <-chan error) {
	t.Helper()
	return startShimWaiting(t, socket, -1)
}

// startShimWaiting is startShim with the time a call waits for an engine
// that went away; negative does not wait.
func startShimWaiting(t *testing.T, socket string, wait time.Duration) (*client, <-chan error) {
	t.Helper()
	return startShimWith(t, socket, shim.Options{ReconnectWait: wait})
}

// startShimWith is startShim with the relay's options.
func startShimWith(t *testing.T, socket string, opts shim.Options) (*client, <-chan error) {
	t.Helper()
	cmds, err := agent.NewCommands("bot", "", "linux", testServiceManager())
	require.NoError(t, err)
	down := agent.EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: time.Now}
	fallback := app.NewEngineDownServer(down)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := shim.ServeWith(context.Background(), socket, fallback, inR, outW, opts)
		_ = outW.Close()
		done <- err
	}()
	t.Cleanup(func() { _ = inW.Close() })
	return &client{in: inW, out: bufio.NewReader(outR)}, done
}

// fakeEngine serves a query tool on socket until the test ends.
func fakeEngine(t *testing.T, socket string) {
	t.Helper()
	fakeEngineMin(t, socket, mcpserver.MinShimProtocol)
}

// fakeEngineMin is fakeEngine serving only shims of protocol minShim or newer.
func fakeEngineMin(t *testing.T, socket string, minShim int) {
	t.Helper()
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "engine"}, mcpserver.Tool{
		Name: "query",
		Call: func(context.Context, json.RawMessage) (any, error) { return map[string]string{"from": "engine"}, nil },
	}).WithMinShimProtocol(minShim)
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}()
		}
	}()
}

func TestShimWithoutAnEngineAnswersItselfThenUsesTheEngineOnceItIsUp(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	c, done := startShim(t, socket)

	init := c.request(t, "initialize", map[string]any{})
	require.Equal(t, "basalt", init["serverInfo"].(map[string]any)["name"], "initialize is answered")
	tools := c.request(t, "tools/list", map[string]any{})["tools"].([]any)
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.(map[string]any)["name"].(string)] = true
	}
	require.True(t, names["status"], "status is listed")
	require.True(t, names["query"], "the contracts' tools are listed")

	body, isError := c.call(t, "query")
	require.True(t, isError)
	require.Equal(t, "UNAVAILABLE", body["code"])
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
	require.NotEmpty(t, body["nextSteps"])
	require.NotEmpty(t, body["personMessage"])

	body, isError = c.call(t, "status")
	require.False(t, isError, "%v", body)
	require.Equal(t, false, body["engine"].(map[string]any)["reachable"])
	require.Equal(t, "UNKNOWN", body["guard"].(map[string]any)["state"])
	require.Equal(t, "PERSON", body["operatedBy"])
	require.Equal(t, "ENGINE_UNREACHABLE", body["problems"].([]any)[0].(map[string]any)["code"])

	// The engine comes up: the very next call reaches it.
	fakeEngine(t, socket)
	body, isError = c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"])

	require.NoError(t, c.in.Close())
	require.NoError(t, <-done)
}

func TestShimFallsBackWhenTheEngineGoesAway(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.Tool{
		Name: "query",
		Call: func(context.Context, json.RawMessage) (any, error) { return map[string]string{"from": "engine"}, nil },
	})
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Answer one line, then stop as a crashed engine would.
		answerFirstRequest(srv, conn)
		conn.Close()
	}()

	c, done := startShim(t, socket)
	body, isError := c.call(t, "query")
	require.False(t, isError)
	require.Equal(t, "engine", body["from"])
	<-engineDone
	require.NoError(t, ln.Close())

	body, isError = c.call(t, "query")
	require.True(t, isError, "%v", body)
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])

	require.NoError(t, c.in.Close())
	err = <-done
	require.True(t, err == nil || errors.Is(err, net.ErrClosed), "%v", err)
}

// answerFirstRequest serves the shim's hello and then one request on conn.
func answerFirstRequest(srv *mcpserver.Server, conn net.Conn) {
	r := bufio.NewReader(conn)
	for range 2 {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		_ = srv.ServeLine(context.Background(), conn, line)
	}
}

// testServiceManager is a service manager with fixed commands: no shim test
// reads them.
func testServiceManager() agent.ServiceManager {
	return agent.ServiceManager{
		StartCommand: func(string) string { return "start-the-engine" },
		RestartArgs:  func(string) []string { return []string{"restart-the-engine"} },
	}
}

// testEngineHost is what the engine-down status reads from the host, fixed.
func testEngineHost() agent.EngineHost {
	return agent.EngineHost{
		LatestGuardVersion: func() int { return 1 },
		StartHoldOffUntil:  func(agent.LastStop, string, time.Time) (time.Time, bool) { return time.Time{}, false },
	}
}
