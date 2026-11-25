package approvalmcp

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/testkit/toolschema"
)

// TestArgsStructsMatchTheSchemas keeps each tool's Go argument struct and its
// contract's input properties in step.
func TestArgsStructsMatchTheSchemas(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"list_pending": listPendingArgs{},
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
		slices.Sort(want)
		require.Equal(t, want, mcptest.JSONFields(v), name)
	}
}

// A held write's list_pending item validates against the tool's closed
// outputSchema: its request by family and the fields the approval binds.
func TestPendingItemMatchesTheSchema(t *testing.T) {
	t.Parallel()
	sch := toolschema.Output(t, "list_pending")
	at := time.Date(2026, 11, 25, 6, 2, 11, 0, time.UTC)
	id := uuid.Must(uuid.NewV7())
	item := pendingFromDomain(approvalsvc.PendingItem{
		Approval: action.Approval{
			ID: id, RunID: uuid.Must(uuid.NewV7()), Intent: "Leads went cold",
			Request:  action.HeldRequest{Kind: "SQL", Text: "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", Params: json.RawMessage(`["closed",21,31]`)},
			Assigned: []string{"status"}, Rows: 11, Status: "PENDING", CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour),
		},
		Notice:        toolresult.ApprovalNotice{ApprovalURL: "http://localhost:8787/approvals/" + id.String(), Headline: "Update 11 rows in public·leads"},
		PersonMessage: "Held for your approval.",
	})
	toolschema.Validate(t, sch, map[string]any{"items": []pendingDTO{item}})
	require.Equal(t, pendingRequestDTO{Kind: "SQL", Params: json.RawMessage(`["closed",21,31]`), Statement: "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3"}, item.Request)
	require.Equal(t, []string{"status"}, item.AssignedFields)
}

// list_pending answers request.kind from the held write, not a constant.
func TestPendingItemKindIsTheHeldWrites(t *testing.T) {
	t.Parallel()
	item := pendingFromDomain(approvalsvc.PendingItem{Approval: action.Approval{
		ID: uuid.Must(uuid.NewV7()), RunID: uuid.Must(uuid.NewV7()),
		Request: action.HeldRequest{Kind: "DOCUMENT", Text: `{"update":"notes"}`},
	}})
	require.Equal(t, pendingRequestDTO{Kind: "DOCUMENT", Statement: `{"update":"notes"}`}, item.Request)
}
