package pluginmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// metaPlugins records the meta request_plugin hands the use case.
type metaPlugins struct {
	got    json.RawMessage
	called bool
}

func (m *metaPlugins) RequestPlugin(_ context.Context, _, _, _ string, _ []string, _ *bool, _ string, _ *int, meta json.RawMessage) (any, error) {
	m.got, m.called = meta, true
	return map[string]any{}, nil
}

// The use case gets the tools/call request's _meta object as the client
// sent it (the files basalt mcp uploaded), and nil for a request without
// one.
func TestRequestPluginGetsTheRequestMeta(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		meta string
		want json.RawMessage
	}{
		"with _meta":    {meta: `,"_meta":{"dev.basaltdb/upload":{"uploadId":"u1","name":"ner"}}`, want: json.RawMessage(`{"dev.basaltdb/upload":{"uploadId":"u1","name":"ner"}}`)},
		"without _meta": {meta: ``, want: nil},
		"empty _meta":   {meta: `,"_meta":{}`, want: json.RawMessage(`{}`)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := &metaPlugins{}
			mount := func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
				return mcpserver.Tool{Name: name, InputSchema: map[string]any{"type": "object"}, Call: call}
			}
			srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, Tools(p, mount)...)
			line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_plugin","arguments":{"source":"/p"}` + tc.meta + `}}`
			var out strings.Builder
			require.NoError(t, srv.ServeLine(context.Background(), &out, []byte(line)))
			require.True(t, p.called, out.String())
			if tc.want == nil {
				require.Nil(t, p.got)
				return
			}
			require.JSONEq(t, string(tc.want), string(p.got))
		})
	}
}
