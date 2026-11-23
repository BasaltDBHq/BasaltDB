package revertmcp

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// TestArgsStructsMatchTheSchemas keeps each tool's Go argument struct and its
// contract's input properties in step.
func TestArgsStructsMatchTheSchemas(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"request_revert": requestRevertArgs{},
		"preview_revert": previewRevertArgs{},
	}
	// Fields a struct decodes only to refuse them with a clear message: the
	// embedded pagination.Params brings sort, which preview_revert refuses
	// (its lines come in their signed order).
	refused := map[string][]string{"preview_revert": {"sort"}}
	for name, v := range args {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		props, ok := c.InputSchema["properties"].(map[string]any)
		require.True(t, ok)
		want := make([]string, 0, len(props)+len(refused[name]))
		for p := range props {
			want = append(want, p)
		}
		want = append(want, refused[name]...)
		sort.Strings(want)
		require.Equal(t, want, jsonFields(v), name)
	}
}

func jsonFields(v any) []string {
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		f := rt.Field(i)
		if f.Anonymous { // an embedded struct (pagination.Params) adds its fields
			out = append(out, jsonFields(reflect.New(f.Type).Elem().Interface())...)
			continue
		}
		out = append(out, strings.Split(f.Tag.Get("json"), ",")[0])
	}
	sort.Strings(out)
	return out
}
