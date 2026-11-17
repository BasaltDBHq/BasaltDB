//go:build linux || darwin

package shim_test

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

// requestError sends one request and returns the JSON-RPC error that comes
// back.
func (c *client) requestError(t *testing.T, method string, params any) *mcp.RPCError {
	t.Helper()
	c.id++
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	require.NoError(t, err)
	_, err = c.in.Write(append(raw, '\n'))
	require.NoError(t, err)
	line, err := c.out.ReadBytes('\n')
	require.NoError(t, err)
	var resp struct {
		ID    int           `json:"id"`
		Error *mcp.RPCError `json:"error"`
	}
	require.NoError(t, json.Unmarshal(line, &resp), string(line))
	require.Equal(t, c.id, resp.ID)
	require.NotNil(t, resp.Error, string(line))
	return resp.Error
}

func TestACurrentShimIsServedByAnEngineThatRequiresIt(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngineMin(t, socket, mcp.ShimProtocol)
	c, done := startShim(t, socket)

	body, isError := c.call(t, "query")
	require.False(t, isError, "%v", body)
	require.Equal(t, "engine", body["from"])

	require.NoError(t, c.in.Close())
	require.NoError(t, <-done)
}

func TestAShimThatNeverSaysHelloIsStillServedByAnEngineThatAcceptsVersionZero(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngine(t, socket)
	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	require.NoError(t, err)
	require.Contains(t, string(line), `"result"`)
}

func TestAnOldShimGetsAnActionableErrorFromANewEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngineMin(t, socket, 1)
	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	r := bufio.NewReader(conn)

	// An old shim sends no hello: its first call is a tool call.
	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"query","arguments":{}}}` + "\n"))
	require.NoError(t, err)
	line, err := r.ReadBytes('\n')
	require.NoError(t, err)
	var resp struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *mcp.RPCError   `json:"error"`
	}
	require.NoError(t, json.Unmarshal(line, &resp), string(line))
	require.Equal(t, 7, resp.ID)
	require.Nil(t, resp.Result, "the call did not run")
	require.NotNil(t, resp.Error)
	require.Equal(t, mcp.ErrCodeVersionMismatch, resp.Error.Code)
	require.Contains(t, resp.Error.Message, "too old")
	require.Contains(t, resp.Error.Message, "Reconnect the MCP server")
	require.Contains(t, resp.Error.Message, "/mcp")

	// Every later request gets the same answer, not a silent drop.
	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":8,"method":"tools/list"}` + "\n"))
	require.NoError(t, err)
	line, err = r.ReadBytes('\n')
	require.NoError(t, err)
	require.Contains(t, string(line), "Reconnect the MCP server")
}

func TestAShimTooOldForTheEngineIsToldToReconnectThroughItsClient(t *testing.T) {
	t.Parallel()
	// A shim at protocol 0 that says hello (a build between the two).
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngineMin(t, socket, 1)
	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	r := bufio.NewReader(conn)
	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":"basalt-hello","method":"basalt/hello","params":{"protocol":0,"build":"0.0.1"}}` + "\n"))
	require.NoError(t, err)
	line, err := r.ReadBytes('\n')
	require.NoError(t, err)
	require.Contains(t, string(line), "0.0.1")
	require.Contains(t, string(line), "Reconnect the MCP server")
}

func TestANewShimTellsTheAgentWhenTheEngineIsTooOld(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngine(t, socket) // protocol 1
	c, done := startShimWith(t, socket, shim.Options{ReconnectWait: -1, MinEngineProtocol: mcp.ShimProtocol + 1})

	e := c.requestError(t, "tools/call", map[string]any{"name": "query", "arguments": map[string]any{}})
	require.Equal(t, mcp.ErrCodeServer, e.Code)
	require.Contains(t, e.Message, "older than this basalt mcp")
	require.Contains(t, e.Message, "restart the basalt engine")
	e = c.requestError(t, "tools/call", map[string]any{"name": "query", "arguments": map[string]any{}})
	require.True(t, strings.Contains(e.Message, "restart the basalt engine"), "later calls get it too: %s", e.Message)

	require.NoError(t, c.in.Close())
	<-done
}

func TestAShimThatTheEngineRefusesIsToldToReconnectNotToRestartTheEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	fakeEngineMin(t, socket, mcp.ShimProtocol+1) // the engine wants a newer shim
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, MinEngineProtocol: 1})

	e := c.requestError(t, "tools/call", map[string]any{"name": "query", "arguments": map[string]any{}})
	require.Equal(t, mcp.ErrCodeVersionMismatch, e.Code)
	require.Contains(t, e.Message, "Reconnect the MCP server")
	require.NotContains(t, e.Message, "restart the basalt engine")
}

func TestAnEngineFromBeforeTheNegotiationIsAProtocolZeroEngine(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Answers every line as an engine that knows no basalt/hello: method not found.
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			req, _ := mcp.RequestOf(line)
			mu.Lock()
			seen = append(seen, req.Method)
			mu.Unlock()
			_ = mcp.WriteError(conn, req.ID, -32601, "method not found: "+req.Method)
		}
	}()
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, MinEngineProtocol: 1})

	e := c.requestError(t, "tools/list", map[string]any{})
	require.Contains(t, e.Message, "restart the basalt engine")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{mcp.HelloMethod}, seen, "the old engine ran nothing")
}
