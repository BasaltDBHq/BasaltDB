//go:build linux || darwin

package shim

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

const testRefusal = `the basalt engine refused this connection: the socket of agent "bot" serves only that agent's OS user`

// refusingEngine listens on socket and refuses the first `refused`
// connections as the engine refuses another OS user: the refusal line, then
// close, without reading a request. Later connections are served a query
// tool.
func refusingEngine(t *testing.T, socket string, refused int) {
	t.Helper()
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "engine"}, mcp.Tool{
		Name: "query",
		Call: func(context.Context, json.RawMessage) (any, error) { return map[string]string{"from": "engine"}, nil },
	})
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for n := 0; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if n < refused {
				_ = mcp.WritePeerRefused(conn, testRefusal)
				conn.Close()
				continue
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}()
		}
	}()
}

// relayLosingRace is the relay Serve runs, except that its first `late`
// dials return only once the engine has ended that session: the request
// then reaches a session that can no longer take it, the order a loaded
// machine produces when the engine's refusal and close win the race.
func relayLosingRace(t *testing.T, socket string, out *strings.Builder, late int) *relay {
	t.Helper()
	cmds, err := agent.NewCommands("bot", "", "linux")
	require.NoError(t, err)
	down := agent.EngineDown{Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: time.Now}
	dials := 0
	return &relay{
		path:     socket,
		fallback: down.Server(mcp.Info{Name: "basalt", Version: "test"}),
		out:      &lineWriter{w: out},
		files:    defaultRequestFiles(),
		dial: func(ctx context.Context, path string, out *lineWriter, fallback Fallback, files requestFiles, neg negotiation) (*session, error) {
			s, err := dial(ctx, path, out, fallback, files, neg)
			dials++
			if err == nil && dials <= late {
				<-s.done
			}
			return s, err
		},
	}
}

func refusalSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bshim") // short: Unix socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "bot.sock")
}

type answer struct {
	ID     any             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *mcp.RPCError   `json:"error"`
}

func answers(t *testing.T, out string) []answer {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	got := make([]answer, 0, len(lines))
	for _, line := range lines {
		var a answer
		require.NoError(t, json.Unmarshal([]byte(line), &a), line)
		got = append(got, a)
	}
	return got
}

func TestARefusalThatArrivesBeforeTheRequestIsForwardedAnswersIt(t *testing.T) {
	t.Parallel()
	socket := refusalSocket(t)
	refusingEngine(t, socket, 1000)
	var out strings.Builder
	r := relayLosingRace(t, socket, &out, 1000)

	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{}}}` + "\n"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := serve(ctx, r, strings.NewReader(in))

	require.NotContains(t, out.String(), "may or may not have run")
	got := answers(t, out.String())
	require.Len(t, got, 2, "one answer per request, none for the notification: %s", out.String())
	for i, a := range got {
		require.EqualValues(t, i+1, a.ID)
		require.Nil(t, a.Result, out.String())
		require.NotNil(t, a.Error, out.String())
		require.Equal(t, mcp.ErrCodeServer, a.Error.Code)
		require.Equal(t, testRefusal, a.Error.Message)
	}
	require.EqualError(t, err, testRefusal, "basalt mcp ends with the refusal")
}

func TestAConnectionAdmittedAfterARefusalIsNotReportedAsRefused(t *testing.T) {
	t.Parallel()
	socket := refusalSocket(t)
	refusingEngine(t, socket, 1)
	var out strings.Builder
	r := relayLosingRace(t, socket, &out, 1)

	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{}}}` + "\n"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := serve(ctx, r, strings.NewReader(in))

	require.NoError(t, err, "the last connection was admitted and ended cleanly")
	got := answers(t, out.String())
	require.Len(t, got, 2, out.String())
	require.EqualValues(t, 1, got[0].ID)
	require.NotNil(t, got[0].Error, out.String())
	require.Equal(t, testRefusal, got[0].Error.Message)
	require.EqualValues(t, 2, got[1].ID)
	require.Nil(t, got[1].Error, out.String())
	require.Contains(t, string(got[1].Result), "engine", "the engine answered")
}
