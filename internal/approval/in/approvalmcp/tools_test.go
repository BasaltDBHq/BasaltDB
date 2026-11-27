package approvalmcp

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
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
		"withdraw":     withdrawArgs{},
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

// fakeWithdrawer answers every withdraw with w, and records the call.
type fakeWithdrawer struct {
	w   action.Withdrawal
	got *approvalsvc.WithdrawParams
}

func (f fakeWithdrawer) Withdraw(_ context.Context, p approvalsvc.WithdrawParams) (approvalsvc.WithdrawResult, error) {
	*f.got = p
	return approvalsvc.WithdrawAnswer(f.w)
}

// withdraw names exactly one of approvalId and revertId: the schema has no
// top-level oneOf, so the handler refuses neither and both.
func TestWithdrawNamesExactlyOneID(t *testing.T) {
	t.Parallel()
	h := handlers{withdraw: fakeWithdrawer{got: &approvalsvc.WithdrawParams{}}}
	id := uuid.Must(uuid.NewV7()).String()
	for name, args := range map[string]string{
		"neither": `{"reason":"no longer needed"}`,
		"both":    `{"approvalId":"` + id + `","revertId":"` + id + `","reason":"no longer needed"}`,
	} {
		_, err := h.withdrawItem(context.Background(), json.RawMessage(args))
		var ae *guidance.ArgumentError
		require.ErrorAs(t, err, &ae, name)
		require.Contains(t, ae.Message, "exactly one of approvalId", name)
	}
	_, err := h.withdrawItem(context.Background(), json.RawMessage(`{"approvalId":"`+id+`"}`))
	var ae *guidance.ArgumentError
	require.ErrorAs(t, err, &ae, "reason is required")
}

// A withdrawn held write answers WITHDRAWN with its reason and time; a
// revert that no longer waited answers its status, without either.
func TestWithdrawResultMatchesTheSchema(t *testing.T) {
	t.Parallel()
	sch := toolschema.Output(t, "withdraw")
	at := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	id := uuid.Must(uuid.NewV7())
	got := &approvalsvc.WithdrawParams{}
	h := handlers{withdraw: fakeWithdrawer{got: got, w: action.Withdrawal{
		Kind: action.WithdrawHeldWrite, ID: id, Status: action.ApprovalWithdrawn, WithdrawnAt: &at, Reason: "the person changed their mind",
	}}}
	out, err := h.withdrawItem(context.Background(), json.RawMessage(`{"approvalId":"`+id.String()+`","reason":"the person changed their mind"}`))
	require.NoError(t, err)
	require.Equal(t, approvalsvc.WithdrawParams{ApprovalID: id, Reason: "the person changed their mind"}, *got)
	res := out.(withdrawResult)
	require.Equal(t, "WITHDRAWN", res.Status)
	require.Equal(t, id.String(), res.ApprovalID)
	require.Equal(t, "the person changed their mind", res.Reason)
	require.Equal(t, "The agent withdrew this request: the person changed their mind. Nothing changed.", res.PersonMessage)
	toolschema.Validate(t, sch, res)

	h = handlers{withdraw: fakeWithdrawer{got: got, w: action.Withdrawal{
		Kind: action.WithdrawRevert, ID: id, Status: action.RevertApplied, WithdrawnAt: &at, Reason: "ignored",
	}}}
	out, err = h.withdrawItem(context.Background(), json.RawMessage(`{"revertId":"`+id.String()+`","reason":"too late"}`))
	require.NoError(t, err)
	res = out.(withdrawResult)
	require.Equal(t, uuid.Nil, got.ApprovalID)
	require.Equal(t, id.String(), res.RevertID)
	require.Empty(t, res.ApprovalID)
	require.Equal(t, "APPLIED", res.Status)
	require.Empty(t, res.WithdrawnAt)
	require.Empty(t, res.Reason)
	require.Equal(t, "This revert no longer waits for your passkey (it is applied), so it was not withdrawn. Nothing changed.", res.PersonMessage)
	toolschema.Validate(t, sch, res)
}
