//go:build linux || darwin

package shim_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// takeAndClose is an engine that reads n requests and closes the
// connection without answering any: a refused peer, or an engine that dies
// mid-call.
func takeAndClose(t *testing.T, socket string, n int) {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(conn)
		// The shim's hello, answered as an engine without it would; then
		// n requests, taken and never answered.
		if _, err := r.ReadBytes('\n'); err != nil {
			conn.Close()
			return
		}
		_ = mcp.WriteError(conn, mcp.HelloID, -32601, "method not found")
		for range n {
			if _, err := r.ReadBytes('\n'); err != nil {
				break
			}
		}
		_ = ln.Close() // before the conn, so no redial can reach a listener nobody serves
		conn.Close()
	}()
}

func TestARequestTheEngineDropsIsAnsweredUnreachable(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	takeAndClose(t, socket, 1)
	c, done := startShim(t, socket)

	// The engine took the call and closed without answering: the client
	// gets an error, never a hang and never a success.
	body, isError := c.call(t, "write")
	require.True(t, isError, "%v", body)
	require.Equal(t, "UNAVAILABLE", body["code"])
	require.Equal(t, "ENGINE_UNREACHABLE", body["reason"])
	require.Contains(t, body["message"], "may or may not have run")
	require.NotEmpty(t, body["nextSteps"])

	require.NoError(t, c.in.Close())
	err := <-done
	require.True(t, err == nil || errors.Is(err, net.ErrClosed), "%v", err)
}

func TestADroppedRequestThatIsNotAToolCallGetsAnError(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	takeAndClose(t, socket, 1)
	c, _ := startShim(t, socket)

	_, err := c.in.Write([]byte(`{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{}}` + "\n"))
	require.NoError(t, err)
	line, err := c.out.ReadBytes('\n')
	require.NoError(t, err)
	var resp struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *mcp.RPCError   `json:"error"`
	}
	require.NoError(t, json.Unmarshal(line, &resp), string(line))
	require.Equal(t, "init-1", resp.ID, "the client's own id")
	require.Nil(t, resp.Result, "never a fake success")
	require.NotNil(t, resp.Error)
	require.Equal(t, mcp.ErrCodeServer, resp.Error.Code)
}
