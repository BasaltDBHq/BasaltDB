package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func TestNoticeOncePerConnectionAndNotOnErrors(t *testing.T) {
	t.Parallel()
	notice := "WARNING: x"
	srv := mcp.NewServer(mcp.Info{Name: "t", Notice: func() string { return notice }},
		mcp.Tool{Name: "ok", Call: func(context.Context, json.RawMessage) (any, error) { return map[string]string{"a": "b"}, nil }},
		mcp.Tool{Name: "bad", Call: func(context.Context, json.RawMessage) (any, error) {
			return nil, &mcp.ToolError{Code: "X", Message: "m"}
		}},
	)
	call := func(name string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `"}}` + "\n"
	}
	run := func(lines ...string) []string {
		var out bytes.Buffer
		require.NoError(t, srv.Serve(context.Background(), strings.NewReader(strings.Join(lines, "")), &out))
		return strings.Split(strings.TrimSpace(out.String()), "\n")
	}
	got := run(call("bad"), call("ok"), call("ok"))
	require.NotContains(t, got[0], "WARNING")
	require.Contains(t, got[1], "WARNING: x")
	require.NotContains(t, got[2], "WARNING")
	// A new connection is a new session.
	require.Contains(t, run(call("ok"))[0], "WARNING: x")
	notice = ""
	require.NotContains(t, run(call("ok"))[0], "WARNING")
}
