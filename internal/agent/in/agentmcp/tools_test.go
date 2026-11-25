package agentmcp

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/testkit/toolschema"
)

// TestArgsStructsMatchTheSchemas keeps each tool's Go argument struct and its
// contract's input properties in step.
func TestArgsStructsMatchTheSchemas(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"run_start": runStartArgs{}, "query": queryArgs{}, "write": writeArgs{},
		"list_runs": action.RunListParams{},
		"describe":  describeArgs{},
	}
	// Fields a struct decodes only to refuse them with a clear message: the
	// embedded pagination.Params brings sort, which describe refuses.
	refused := map[string][]string{"describe": {"sort"}}
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

// A list_runs item validates against the tool's outputSchema, with the
// resources it wrote and, past the cap, resourcesTruncated.
func TestRunSummaryMatchesTheSchema(t *testing.T) {
	t.Parallel()
	sch := toolschema.Output(t, "list_runs")
	at := time.Date(2026, 11, 25, 6, 2, 11, 0, time.UTC)
	full := runSummaryFromDomain(action.RunSummary{
		ID: uuid.Must(uuid.NewV7()), TaskID: uuid.NullUUID{UUID: uuid.Must(uuid.NewV7()), Valid: true}, Intent: "Tidy",
		StartedAt: at, LastChangeAt: &at, Applied: 2, Reads: 1, RowsWritten: 4,
		Resources: []string{"public.leads"}, ResourcesTruncated: true,
	})
	empty := runSummaryFromDomain(action.RunSummary{ID: uuid.Must(uuid.NewV7()), Intent: "Nothing yet", StartedAt: at})
	toolschema.Validate(t, sch, map[string]any{"items": []runSummaryDTO{full, empty}})
	require.Equal(t, []string{}, empty.Resources, "an empty list, never null")
}
