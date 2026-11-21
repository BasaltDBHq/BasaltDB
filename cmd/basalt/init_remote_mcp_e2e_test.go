//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// Running the mcpCommand returned by init --remote, as the agent's user,
// reaches the engine (basalt mcp starts it and status answers).
func TestInitRemoteMCPCommandReachesTheEngine(t *testing.T) {
	t.Setenv(testAsBasaltEnv, "1")
	d, dbURL := remoteDB(t)
	dir, err := os.MkdirTemp("", "brmcp")
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	h := newFakeHost(t)
	cfg := filepath.Join(dir, "engine.json")
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return d.URL
			}
			return ""
		})
	c.host = h
	code := runInit(c, []string{
		"--remote", "--config", cfg, "--json",
		"--operated-by", "agent", "--vault", "off",
		"--agent", "bot", "--write", "public.leads",
		"--prefix", d.Names.Prefix, "--database-url", dbURL,
	})
	require.Equal(t, exitOK, code, stderr.String())
	res := decodeRemoteResult(t, stdout.String())
	abs, err := filepath.Abs(cfg)
	require.NoError(t, err)
	require.Equal(t, []string{
		"basalt", "mcp", "--agent", "bot",
		"--socket-dir", filepath.Join(dir, "run"),
		"--config", abs,
	}, res.MCPCommand)

	_, reg := portalPasskey(t, dbName(t, d))
	done := laptopRun(t, d.URL, reg+"\n", time.Time{}, "--setup-code", res.Code, "--yes")
	require.Equal(t, exitOK, done.code, done.stderr)

	socketDir := filepath.Join(dir, "run")
	t.Cleanup(func() {
		if pid, up, _ := server.Running(engine.LockPath(socketDir)); up {
			if ppid, err := parentOf(pid); err == nil {
				_ = syscall.Kill(ppid, syscall.SIGTERM)
			}
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	})

	in, inW := io.Pipe()
	var errBuf bytes.Buffer
	outR, outW := io.Pipe()
	exited := make(chan int, 1)
	go func() {
		// argv is the printed command without the program and "mcp" subcommand.
		exited <- runMCPOn(context.Background(), res.MCPCommand[2:], stdio{in: in, out: outW, err: &errBuf}, osHost{})
		_ = outW.Close()
	}()
	_, err = fmt.Fprintf(inW, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(outR)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line+errBuf.String())
	require.Len(t, resp.Result.Content, 1, line+errBuf.String())
	var report struct {
		Ready  bool `json:"ready"`
		Engine struct {
			Reachable bool `json:"reachable"`
		} `json:"engine"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &report))
	require.True(t, report.Engine.Reachable, resp.Result.Content[0].Text)
	require.True(t, report.Ready, resp.Result.Content[0].Text)

	require.NoError(t, inW.Close())
	require.Equal(t, exitOK, <-exited, errBuf.String())
}
