package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

func serve(t *testing.T, s *mcp.Server, lines ...string) []mcp.Response {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")), &out))
	var resps []mcp.Response
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r mcp.Response
		require.NoError(t, dec.Decode(&r))
		resps = append(resps, r)
	}
	return resps
}

func toolText(t *testing.T, result any) (string, bool) {
	t.Helper()
	m, ok := result.(map[string]any)
	require.True(t, ok)
	content, ok := m["content"].([]any)
	require.True(t, ok)
	first, ok := content[0].(map[string]any)
	require.True(t, ok)
	text, ok := first["text"].(string)
	require.True(t, ok)
	isError, ok := m["isError"].(bool)
	require.True(t, ok)
	return text, isError
}

func TestServeInitializeListAndCall(t *testing.T) {
	t.Parallel()
	echo := mcp.Tool{
		Name: "echo",
		Call: func(_ context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Say string `json:"say"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return nil, err
			}
			if a.Say == "" {
				return nil, &toolresult.ToolError{Code: "INVALID_ARGUMENT", Message: "say is required"}
			}
			return map[string]string{"said": a.Say}, nil
		},
	}
	fails := mcp.Tool{Name: "fails", Call: func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("boom") }}
	s := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, echo, fails)

	resps := serve(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"say":"hi"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fails"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}`,
		`{"jsonrpc":"2.0","id":7,"method":"nope"}`,
		`not json`,
	)
	require.Len(t, resps, 8)

	initRes, ok := resps[0].Result.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "2025-06-18", initRes["protocolVersion"])

	list, ok := resps[1].Result.(map[string]any)
	require.True(t, ok)
	require.Len(t, list["tools"], 2)

	text, isError := toolText(t, resps[2].Result)
	require.False(t, isError)
	require.JSONEq(t, `{"said":"hi"}`, text)

	text, isError = toolText(t, resps[3].Result)
	require.True(t, isError)
	require.JSONEq(t, `{"code":"INVALID_ARGUMENT","message":"say is required","docsUrl":"https://docs.basaltvault.app/reference/errors/#invalid-argument"}`, text)

	text, isError = toolText(t, resps[4].Result)
	require.True(t, isError)
	require.JSONEq(t, `{"message":"boom"}`, text)

	require.NotNil(t, resps[5].Error)
	require.NotNil(t, resps[6].Error)
	require.NotNil(t, resps[7].Error)
}

func TestNewServerRefusesDuplicateTools(t *testing.T) {
	t.Parallel()
	tool := mcp.Tool{Name: "x", Call: func(context.Context, json.RawMessage) (any, error) { return struct{}{}, nil }}
	require.Panics(t, func() { mcp.NewServer(mcp.Info{}, tool, tool) })
}

func TestDocsURLAnchorsTheCode(t *testing.T) {
	t.Parallel()
	require.Equal(t, "https://docs.basaltvault.app/reference/errors/#approval-required", toolresult.DocsURL("APPROVAL_REQUIRED"))
	require.Equal(t, "https://docs.basaltvault.app/reference/errors/#internal", toolresult.DocsURL("INTERNAL"))
}
