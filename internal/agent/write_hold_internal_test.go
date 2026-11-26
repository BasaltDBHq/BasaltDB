package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// refusalLedger keeps the refusals the agent records.
type refusalLedger struct {
	Ledger
	refusals []action.Refusal
}

func (l *refusalLedger) RecordRefusal(_ context.Context, r action.Refusal) error {
	l.refusals = append(l.refusals, r)
	return nil
}

// failingNamesLedger fails every refusal that names resources, as a
// ledger whose qualification of the names fails would.
type failingNamesLedger struct {
	refusalLedger
	calls int
}

func (l *failingNamesLedger) RecordRefusal(ctx context.Context, r action.Refusal) error {
	l.calls++
	if len(r.Resources) > 0 {
		return errors.New("the names could not be qualified")
	}
	return l.refusalLedger.RecordRefusal(ctx, r)
}

// fixedHolds is the approval's store with a fixed preview and hold result.
type fixedHolds struct {
	approvalsvc.Store
	preview    approvalstore.HeldPreview
	previewErr error
	holdErr    error
}

func (s fixedHolds) Preview(context.Context, action.Intent, agentstore.Request) (approvalstore.HeldPreview, error) {
	return s.preview, s.previewErr
}

func (s fixedHolds) Hold(context.Context, action.Intent, approvalstore.HoldRequest) (approvalstore.Held, error) {
	return approvalstore.Held{}, s.holdErr
}

// The seven ways a hold can fail before it is held, through the approval
// use case to the agent: each keeps its answer, and the agent records a
// refused write for exactly the ones it recorded before the hold was one
// call (not repeatable, the preview run failing, over the cap).
func TestHoldExitsRecordWhatTheyRecordedBefore(t *testing.T) {
	t.Parallel()
	notRepeatable := &action.RefusalError{Reason: action.ReasonNotRepeatable, Detail: "now() gives another value"}
	// Every store error below has a code the agent records when it is asked
	// to: one that is not recorded was never handed to refused.
	catalog := &action.StoreError{Code: guidance.CodeStoreError, Message: "the catalog read failed"}
	run := &action.StoreError{Code: guidance.CodeStoreError, Message: "the preview failed"}
	olderGuard := &action.StoreError{Code: guidance.CodeStoreError, Message: "each line must be the jsonb text of a preview line"}
	guardTooLarge := &toolresult.ToolError{Code: guidance.CodeStatementRefused, Reason: action.ReasonHoldTooLarge, Message: "the guard refused the lines"}
	for _, tc := range []struct {
		name     string
		store    fixedHolds
		code     string
		reason   string
		recorded bool
	}{
		{"not repeatable", fixedHolds{previewErr: notRepeatable}, guidance.CodeStatementRefused, string(action.ReasonNotRepeatable), true},
		{"catalog read failing", fixedHolds{previewErr: catalog}, guidance.CodeStoreError, "", false},
		{"preview run failing", fixedHolds{previewErr: &approvalstore.PreviewFailedError{Err: run}}, guidance.CodeStoreError, "", true},
		{"no rows now", fixedHolds{}, guidance.CodeStoreError, guidance.ReasonNoRowsNow, false},
		{"over the cap", fixedHolds{preview: approvalstore.HeldPreview{Lines: []string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes+1)}}}, guidance.CodeStatementRefused, action.ReasonHoldTooLarge, true},
		// Unreachable in practice: admission refuses a guard from before the
		// 64 MiB cap (64 KiB a line) before any hold. Not a regression.
		{"the hold failing on a long line", fixedHolds{preview: approvalstore.HeldPreview{Lines: []string{strings.Repeat("x", 64<<10+1)}}, holdErr: olderGuard}, guidance.CodeStoreError, "", false},
		{"the guard's own cap", fixedHolds{preview: approvalstore.HeldPreview{Lines: []string{"x"}}, holdErr: guardTooLarge}, guidance.CodeStatementRefused, action.ReasonHoldTooLarge, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ledger := &refusalLedger{}
			approvals := approvalsvc.New(approvalsvc.Core{}, approvalsvc.StoreSet{Records: tc.store, Holds: tc.store, Proofs: tc.store}, &approvalsvc.Deps{}, nil, nil, nil, nil)
			wc := newTestService(t, "linux", "", func(s *settings) { s.store.Ledger, s.approvals = ledger, approvals })
			req := agentstore.Request{Text: "DELETE FROM public.leads WHERE id = $1", Params: []any{1}}
			in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "drop a lead"}

			stmt := action.Statement{Op: action.OpDelete, Tables: []string{"public.leads"}}
			id, _, err := wc.hold(context.Background(), in, WriteParams{Request: req}, stmt, wc.core.Now())
			require.Equal(t, uuid.Nil, id)
			var hr *approvalsvc.HoldRefusalError
			require.False(t, errors.As(err, &hr), "the agent answers with the refusal itself")
			te := wc.core.Errors.ToolError(err)
			require.Equal(t, tc.code, te.Code)
			require.Equal(t, tc.reason, te.Reason)
			if !tc.recorded {
				require.Empty(t, ledger.refusals)
				return
			}
			require.Len(t, ledger.refusals, 1)
			r := ledger.refusals[0]
			require.Equal(t, tc.code, r.Code)
			require.Equal(t, action.OpDelete, r.Op)
			require.Equal(t, req.Text, r.Statement)
			require.Equal(t, in, r.Intent)
			require.Equal(t, stmt.Tables, r.Resources)
		})
	}
}

// A refusal is recorded with the resources the store's check gave the
// statement, as written (the store qualifies them when it records); a
// statement the check could not parse names none.
func TestRefusedRecordsTheStatementsResources(t *testing.T) {
	t.Parallel()
	refusal := &action.RefusalError{Reason: action.ReasonFunction, Detail: "pg_sleep is not on the function allowlist"}
	parse := &action.RefusalError{Reason: action.ReasonParseError, Detail: "syntax error at or near \"FORM\""}
	for _, tc := range []struct {
		name string
		stmt action.Statement
		err  error
		want []string
	}{
		{"a refused read", action.Statement{Op: action.OpRead, Tables: []string{"leads"}}, refusal, []string{"leads"}},
		{"a refused write", action.Statement{Op: action.OpDelete, Tables: []string{"leads", "sales.orders"}, Target: "leads"}, refusal, []string{"leads", "sales.orders"}},
		// The target first, as a write's own record names it: another table
		// that sorts earlier cannot become the refusal's resource.
		{"a refused write with another table", action.Statement{Op: action.OpUpdate, Tables: []string{"audit_log", "payroll"}, Target: "payroll"}, refusal, []string{"payroll", "audit_log"}},
		{"an unparseable statement", action.Statement{}, parse, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ledger := &refusalLedger{}
			wc := newTestService(t, "linux", "", func(s *settings) { s.store.Ledger = ledger })
			in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "tidy the leads"}
			req := agentstore.Request{Text: "DELETE FROM leads"}

			err := wc.refused(context.Background(), in, tc.stmt, req, wc.core.Now(), tc.err)
			require.Equal(t, tc.err, err)
			require.Len(t, ledger.refusals, 1)
			require.Equal(t, tc.want, ledger.refusals[0].Resources)
			require.Equal(t, refusalOp(tc.stmt.Op), ledger.refusals[0].Op)
		})
	}
}

// DIFFERENT_WRITE's step sends the held request back as it was held: a
// parameter past 2^53 keeps its exact value through the step's JSON, and
// the write the step makes is the held one.
func TestDifferentWriteStepKeepsExactNumbers(t *testing.T) {
	t.Parallel()
	wc := newTestService(t, "linux", "")
	held := action.Approval{
		ID: uuid.Must(uuid.NewV7()), RunID: uuid.Must(uuid.NewV7()), Status: action.ApprovalPending,
		Request: action.HeldRequest{Kind: "SQL", Text: "DELETE FROM public.leads WHERE id = $1", Params: json.RawMessage(`[9007199254740993]`)},
	}

	// A call with another text gets DIFFERENT_WRITE, whose step sends the
	// held write back.
	other := WriteParams{RunID: held.RunID, Request: agentstore.Request{Text: "DELETE FROM public.leads WHERE id = 1"}}
	var te *toolresult.ToolError
	require.ErrorAs(t, wc.sameAsHeld(held, other), &te)
	require.Equal(t, guidance.ReasonDifferentWrite, te.Reason)
	require.Len(t, te.NextSteps, 1)
	raw, err := json.Marshal(te.NextSteps[0].Arguments)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"params":[9007199254740993]`)

	// The agent sends the step's arguments back as the write tool decodes
	// them (numbers kept exact).
	var call struct {
		SQL    string          `json:"sql"`
		Params json.RawMessage `json:"params"`
	}
	require.NoError(t, json.Unmarshal(raw, &call))
	again := WriteParams{RunID: held.RunID, Request: agentstore.Request{Text: call.SQL, Params: callParams(t, string(call.Params))}}
	require.NoError(t, wc.sameAsHeld(held, again), "the step's write is the held one")

	rounded := WriteParams{RunID: held.RunID, Request: agentstore.Request{Text: call.SQL, Params: callParams(t, `[9007199254740992]`)}}
	require.Error(t, wc.sameAsHeld(held, rounded))
}

// A refusal whose names make recording fail is recorded once more without
// them: no name keeps a refusal out of the ledger.
func TestRefusedIsRecordedWithoutNamesWhenTheyFail(t *testing.T) {
	t.Parallel()
	ledger := &failingNamesLedger{}
	wc := newTestService(t, "linux", "", func(s *settings) { s.store.Ledger = ledger })
	in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "tidy the leads"}
	refusal := &action.RefusalError{Reason: action.ReasonFunction, Detail: "pg_sleep is not on the function allowlist"}
	stmt := action.Statement{Op: action.OpDelete, Tables: []string{"leads"}, Target: "leads"}

	err := wc.refused(context.Background(), in, stmt, agentstore.Request{Text: "DELETE FROM leads"}, wc.core.Now(), refusal)
	require.Equal(t, refusal, err, "the agent still gets its refusal")
	require.Equal(t, 2, ledger.calls)
	require.Len(t, ledger.refusals, 1)
	require.Empty(t, ledger.refusals[0].Resources)
	require.Equal(t, "DELETE FROM leads", ledger.refusals[0].Statement)
}
