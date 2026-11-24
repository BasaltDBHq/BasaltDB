package mcpserver_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

const callBoom = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`

func boomTool() mcpserver.Tool {
	return mcpserver.Tool{Name: "boom", Call: func(context.Context, json.RawMessage) (any, error) {
		panic("row value: alice@example.com")
	}}
}

// TestToolPanicEndsTheCallNotTheEngine: with OnPanic set, a tool that panics
// answers INTERNAL, tells the person which report to read, and the server
// goes on serving; the answer carries nothing the panic carried.
func TestToolPanicEndsTheCallNotTheEngine(t *testing.T) {
	t.Parallel()
	var gotTool string
	var gotValue any
	var gotStack []byte
	s := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "1", OnPanic: func(tool string, v any, stack []byte) string {
		gotTool, gotValue, gotStack = tool, v, stack
		return "report-id-1"
	}}, boomTool())
	resps := serve(t, s, callBoom, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	require.Len(t, resps, 2, "the server answered the next request")

	text, isError := toolText(t, resps[0].Result)
	require.True(t, isError)
	require.Equal(t, "boom", gotTool)
	require.Contains(t, gotValue, "alice@example.com")
	require.Contains(t, string(gotStack), "boomTool")

	require.NotContains(t, text, "alice@example.com")
	var te toolresult.ToolError
	require.NoError(t, json.Unmarshal([]byte(text), &te))
	require.Equal(t, "INTERNAL", te.Code)
	require.Contains(t, te.PersonMessage, "report-id-1")
	require.Contains(t, te.PersonMessage, "status tool")
	require.NotContains(t, te.PersonMessage, "basalt crash")
	require.NotEmpty(t, te.NextSteps)
}

func TestToolPanicWithoutAReportStillAnswersInternal(t *testing.T) {
	t.Parallel()
	s := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "1", OnPanic: func(string, any, []byte) string { return "" }}, boomTool())
	text, isError := toolText(t, serve(t, s, callBoom)[0].Result)
	require.True(t, isError)
	var te toolresult.ToolError
	require.NoError(t, json.Unmarshal([]byte(text), &te))
	require.Equal(t, "INTERNAL", te.Code)
	require.Empty(t, te.PersonMessage)
}

// TestToolPanicIsNotRecoveredWithoutOnPanic: no hook, no change in behavior.
func TestToolPanicIsNotRecoveredWithoutOnPanic(t *testing.T) {
	t.Parallel()
	s := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "1"}, boomTool())
	require.Panics(t, func() { _ = s.ServeLine(context.Background(), discard{}, []byte(callBoom)) })
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
