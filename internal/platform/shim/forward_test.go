//go:build linux || darwin

package shim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// An engine that stops for a restart closes the shim's connection. When the
// shim's reader sees that end while the next request is being written, the
// write fails: the request never reached the engine, so it goes to the engine
// that comes back instead of being answered as dropped.
func TestARequestThatNeverReachedAClosedEngineGoesToTheNextOne(t *testing.T) {
	t.Parallel()
	socket := refusalSocket(t)
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = ln.Close() })

	var oldWrites atomic.Int32
	build := func(name string) *mcpserver.Server {
		return mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: name}, mcpserver.Tool{
			Name: "write",
			Call: func(context.Context, json.RawMessage) (any, error) {
				if name == "old" {
					oldWrites.Add(1)
				}
				return map[string]string{"from": name}, nil
			},
		})
	}
	first := make(chan net.Conn, 1)
	go func() {
		for n := 0; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv := build("new")
			if n == 0 {
				srv = build("old")
				first <- conn
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}()
		}
	}()

	cmds, err := agent.NewCommands("bot", "", "linux", testServiceManager())
	require.NoError(t, err)
	down := agent.EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: time.Now}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	r := &relay{
		path: socket, fallback: app.NewEngineDownServer(down),
		out: &lineWriter{w: outW}, files: defaultRequestFiles(),
		reconnectWait: 5 * time.Second, retries: make(chan []byte, retryQueue), retried: map[string]bool{},
	}
	var dials atomic.Int32
	r.dial = func(ctx context.Context, path string, out *lineWriter, fallback Fallback, files requestFiles, neg negotiation) (*session, error) {
		s, err := dial(ctx, path, out, fallback, files, neg)
		if dials.Add(1) == 1 && err == nil {
			writes := 0
			s.beforeWrite = func() {
				if writes++; writes != 2 {
					return
				}
				// The old engine closes the connection as the second
				// request is about to be written, and the shim's reader
				// gets the time to see the end.
				(<-first).Close()
				select {
				case <-s.done:
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
		return s, err
	}
	served := make(chan error, 1)
	go func() {
		served <- serve(ctx, r, inR)
		_ = outW.Close()
	}()
	read := json.NewDecoder(outR)
	call := func(id int) answer {
		t.Helper()
		_, err := fmt.Fprintf(inW, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"write","arguments":{}}}`+"\n", id)
		require.NoError(t, err)
		var a answer
		require.NoError(t, read.Decode(&a))
		require.EqualValues(t, id, a.ID)
		return a
	}

	a := call(1)
	require.Nil(t, a.Error)
	require.Contains(t, string(a.Result), "old")
	a = call(2)
	require.Nil(t, a.Error, "%s", a.Result)
	require.Contains(t, string(a.Result), "new", "the engine that came back ran it")
	require.EqualValues(t, 1, oldWrites.Load())
	require.EqualValues(t, 2, dials.Load())
	require.NoError(t, inW.Close())
	require.NoError(t, <-served)
}

// testServiceManager is a service manager with fixed commands: no shim test
// reads them.
func testServiceManager() guidance.ServiceManager {
	return guidance.ServiceManager{
		StartCommand: func(string) string { return "start-the-engine" },
		RestartArgs:  func(string) []string { return []string{"restart-the-engine"} },
	}
}

// testEngineHost is what the engine-down status reads from the host, fixed.
func testEngineHost() agent.EngineHost {
	return agent.EngineHost{
		LatestGuardVersion: func() int { return 1 },
		StartHoldOffUntil:  func(guidance.LastStop, string, time.Time) (time.Time, bool) { return time.Time{}, false },
	}
}
