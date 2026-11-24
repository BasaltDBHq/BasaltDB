package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A tool sees the _meta of its tools/call request, and nothing without one.
func TestToolSeesTheCallsMeta(t *testing.T) {
	t.Parallel()
	var seen []json.RawMessage
	s := NewServer(Info{Name: "t"}, Tool{Name: "echo", Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
		seen = append(seen, Meta(ctx))
		return map[string]string{}, nil
	}})
	for _, params := range []string{`{"name":"echo","arguments":{},"_meta":{"k":1}}`, `{"name":"echo","arguments":{}}`} {
		_, rpcErr := s.callTool(context.Background(), json.RawMessage(params), nil)
		require.Nil(t, rpcErr)
	}
	require.Len(t, seen, 2)
	require.JSONEq(t, `{"k":1}`, string(seen[0]))
	require.Nil(t, seen[1])
}
