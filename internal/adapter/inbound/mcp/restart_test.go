package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
)

// countingGate admits the first open requests and counts what it saw.
type countingGate struct {
	open        int
	begun, ends int
}

func (g *countingGate) Begin() bool {
	g.begun++
	return g.begun <= g.open
}

func (g *countingGate) End() { g.ends++ }

func TestAGatedServerAnswersRefusedRequestsAsNotRun(t *testing.T) {
	t.Parallel()
	ran := 0
	write := mcp.Tool{Name: "write", Call: func(context.Context, json.RawMessage) (any, error) {
		ran++
		return map[string]string{"ok": "yes"}, nil
	}}
	s := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, write)
	g := &countingGate{open: 1}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"basalt-hello","method":"basalt/hello","params":{"protocol":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write"}}`,
	}, "\n")
	var out bytes.Buffer
	require.NoError(t, s.ServeGated(context.Background(), strings.NewReader(in), &out, g))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3, "hello, the run call and the refused one: %s", out.String())
	require.Contains(t, lines[0], `"minShimProtocol"`, "the hello is not gated")
	require.Contains(t, lines[1], `"id":1,"result"`)
	id, ok := mcp.Restarting([]byte(lines[2]))
	require.True(t, ok, lines[2])
	require.Equal(t, "2", id)
	require.Contains(t, lines[2], "Nothing was run")
	require.Equal(t, 1, ran, "the refused call never ran")
	require.Equal(t, 2, g.begun, "notifications and the hello are not gated")
	require.Equal(t, 1, g.ends, "End only for an admitted request")
}

func TestRestartingReadsOnlyTheRestartingCode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line string
		id   string
		ok   bool
	}{
		{`{"jsonrpc":"2.0","id":7,"error":{"code":-32003,"message":"x"}}`, "7", true},
		{`{"jsonrpc":"2.0","id":"a","error":{"code":-32003,"message":"x"}}`, `"a"`, true},
		{`{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"x"}}`, "", false},
		{`{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x"}}`, "", false},
		{`{"jsonrpc":"2.0","id":7,"result":{}}`, "", false},
		{`not json`, "", false},
	} {
		id, ok := mcp.Restarting([]byte(tc.line))
		require.Equal(t, tc.ok, ok, tc.line)
		require.Equal(t, tc.id, id, tc.line)
	}
}
