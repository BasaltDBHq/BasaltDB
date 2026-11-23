package ledgermcp

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
		"run_history": runHistoryArgs{},
	}
	for name, v := range args {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		props, ok := c.InputSchema["properties"].(map[string]any)
		require.True(t, ok)
		want := make([]string, 0, len(props))
		for p := range props {
			want = append(want, p)
		}
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
