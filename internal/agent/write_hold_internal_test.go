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

// fixedHolds is the approval's store with a fixed preview and hold result.
type fixedHolds struct {
	approvalsvc.Store
	preview    action.HeldPreview
	previewErr error
	holdErr    error
}

func (s fixedHolds) Preview(context.Context, action.Intent, agentstore.Request) (action.HeldPreview, error) {
	return s.preview, s.previewErr
}

func (s fixedHolds) Hold(context.Context, action.Intent, action.HoldRequest) (action.Held, error) {
	return action.Held{}, s.holdErr
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
		{"preview run failing", fixedHolds{previewErr: &action.PreviewFailedError{Err: run}}, guidance.CodeStoreError, "", true},
		{"no rows now", fixedHolds{}, guidance.CodeStoreError, guidance.ReasonNoRowsNow, false},
		{"over the cap", fixedHolds{preview: action.HeldPreview{Lines: []string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes+1)}}}, guidance.CodeStatementRefused, action.ReasonHoldTooLarge, true},
		// Unreachable in practice: admission refuses a guard from before the
		// 64 MiB cap (64 KiB a line) before any hold. Not a regression.
		{"the hold failing on a long line", fixedHolds{preview: action.HeldPreview{Lines: []string{strings.Repeat("x", 64<<10+1)}}, holdErr: olderGuard}, guidance.CodeStoreError, "", false},
		{"the guard's own cap", fixedHolds{preview: action.HeldPreview{Lines: []string{"x"}}, holdErr: guardTooLarge}, guidance.CodeStatementRefused, action.ReasonHoldTooLarge, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ledger := &refusalLedger{}
			wc := newTestService(t, "linux", "", func(s *settings) { s.store.Ledger = ledger })
			approvals := approvalsvc.New(approvalsvc.Core{}, approvalsvc.StoreSet{Records: tc.store, Holds: tc.store, Proofs: tc.store}, &approvalsvc.Deps{}, nil, nil)
			wc.SetPorts(nil, approvals, nil, nil, nil)
			req := agentstore.Request{Text: "DELETE FROM public.leads WHERE id = $1", Params: []any{1}}
			in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "drop a lead"}

			id, _, err := wc.hold(context.Background(), in, WriteParams{Request: req}, action.Statement{Op: action.OpDelete}, wc.core.Now())
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
