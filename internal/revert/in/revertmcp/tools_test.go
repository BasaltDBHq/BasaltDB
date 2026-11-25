package revertmcp

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
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
		slices.Sort(want)
		require.Equal(t, want, mcptest.JSONFields(v), name)
	}
}

// The tools hold no rule for a table name: the agent's string reaches the
// scope unchanged, and the store refuses a name it cannot use. The tool
// schemas carry no name pattern either.
func TestTableNamesPassThroughToTheStore(t *testing.T) {
	t.Parallel()
	names := []string{"leads", "public.leads;drop", "a b.c", "public.leads", "s.t.u", "Public.\"Leads\""}
	for _, kind := range []revert.Scope{revert.ScopeChange, revert.ScopeRun, revert.ScopeTask} {
		scope, err := scopeIDs{Tables: names}.filtered(action.Scope{Kind: kind, ID: uuid.Must(uuid.NewV7())})
		require.NoError(t, err, kind)
		require.Equal(t, names, scope.Tables, kind)
	}
	for _, name := range []string{"preview_revert", "request_revert"} {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		tables := c.InputSchema["properties"].(map[string]any)["tables"].(map[string]any)
		require.Equal(t, map[string]any{"type": "string"}, tables["items"], name)
	}
}
