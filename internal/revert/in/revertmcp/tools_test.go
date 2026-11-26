package revertmcp

import (
	"encoding/json"
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

// The tools hold no rule for a resource name: the agent's string reaches
// the scope unchanged, and the store refuses a name it cannot use. The tool
// schemas carry no name pattern either.
func TestResourceNamesPassThroughToTheStore(t *testing.T) {
	t.Parallel()
	names := []string{"leads", "public.leads;drop", "a b.c", "public.leads", "s.t.u", "Public.\"Leads\""}
	for _, kind := range []revert.Scope{revert.ScopeChange, revert.ScopeRun, revert.ScopeTask} {
		scope, err := scopeIDs{Resources: names}.filtered(action.Scope{Kind: kind, ID: uuid.Must(uuid.NewV7())})
		require.NoError(t, err, kind)
		require.Equal(t, names, scope.Resources, kind)
	}
	for _, name := range []string{"preview_revert", "request_revert"} {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		resources := c.InputSchema["properties"].(map[string]any)["resources"].(map[string]any)
		require.Equal(t, map[string]any{"type": "string"}, resources["items"], name)
	}
}

// The agent reads a line's store code as storeCode and its resource as
// resource: the signed line's store.code and resource map to them, on preview
// lines, plan items, a plan item's plan line and batch items.
func TestRevertAnswersNameStoreCodeAndResource(t *testing.T) {
	t.Parallel()
	code, conflict := "23505", "KEY_TAKEN"
	line := revert.Line{Action: "SKIP", Op: "INSERT", Resource: "public.leads", Conflict: &conflict, Store: revert.LineStore{Kind: "POSTGRES", Verb: "INSERT", Code: &code}}
	got, err := json.Marshal(revertLineFromDomain(line))
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(got, &fields))
	require.Equal(t, "public.leads", fields["resource"])
	require.Equal(t, code, fields["storeCode"])
	require.NotContains(t, fields, "table")
	require.NotContains(t, fields, "sqlState")

	plan, err := json.Marshal(revertPlanItemDTO{Line: 1, Outcome: "SKIPPED", Conflict: conflict, StoreCode: code})
	require.NoError(t, err)
	require.JSONEq(t, `{"line": 1, "outcome": "SKIPPED", "conflict": "KEY_TAKEN", "storeCode": "23505"}`, string(plan))

	item, err := json.Marshal(action.BatchItem{Line: 1, Outcome: "SKIPPED", Conflict: conflict, StoreCode: code})
	require.NoError(t, err)
	require.JSONEq(t, `{"line": 1, "outcome": "SKIPPED", "conflict": "KEY_TAKEN", "storeCode": "23505"}`, string(item))
}
