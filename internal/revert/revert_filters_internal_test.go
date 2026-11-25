package revert

import (
	"errors"
	"strings"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// A request made from the steps keeps the filters the person was shown:
// the preview's REVISE_CALL, and requesting an expired or changed revert
// again, carry runs and resources.
func TestRevertStepsKeepTheFilters(t *testing.T) {
	t.Parallel()
	run := uuid.MustParse(caseRunID)
	scope := action.Scope{Kind: revert.ScopeTask, ID: run, Runs: []uuid.UUID{run}, Tables: []string{"public.leads", "public.lead_owner"}}
	require.Equal(t, map[string]any{"taskId": caseRunID, "runs": []string{caseRunID}, "resources": []string{"public.leads", "public.lead_owner"}},
		scopeArgs(scope))
	require.Equal(t, map[string]any{"runId": caseRunID}, scopeArgs(action.Scope{Kind: revert.ScopeRun, ID: run}))

	msg, steps, err := newService(t, "linux", "").previewGuidance(RevertPreview{Scope: scope, Rows: 2})
	require.NoError(t, err)
	require.Equal(t, scopeArgs(scope), steps[1].Arguments, "the request the person agrees to is the one previewed")
	require.Contains(t, msg, "task "+caseRunID+", only 1 of its runs and tables public·leads and 1 more would restore")
	require.NotContains(t, msg, "basalt ", "the person runs no command")

	r := revertOf(t, "Undo", []string{changedAfterLine}, false)
	r.BindingText = strings.Replace(r.BindingText, `"tables": null`, `"tables": ["public.lead_owner"]`, 1)
	want := map[string]any{"runId": caseRunID, "resources": []string{"public.lead_owner"}}
	require.Equal(t, want, expiredSteps(r)[1].Arguments)
	var te *toolresult.ToolError
	require.True(t, errors.As(newService(t, "linux", "").rowsChanged(r, "rows changed since"), &te))
	require.Equal(t, want, te.NextSteps[0].Arguments)
	require.Contains(t, te.PersonMessage, "run "+caseRunID+", only table public·lead_owner, so nothing was reverted")

	r.BindingText = ""
	require.Equal(t, map[string]any{"runId": caseRunID}, expiredSteps(r)[1].Arguments, "a widened revert's binding is hidden")
}

// The guard's refusal of a scope becomes the agent's argument error, with the
// reason the catalog's next steps are keyed by.
func TestScopeRefusedGivesTheFilterReasons(t *testing.T) {
	t.Parallel()
	scope := action.Scope{Kind: revert.ScopeRun, ID: uuid.MustParse(caseRunID)}
	refuse := func(reason action.RevertReason, detail string) error {
		return scopeRefused(scope, action.RevertRefusalError{Reason: reason, Detail: detail})
	}

	var ae *guidance.ArgumentError
	require.ErrorAs(t, refuse(action.RevertFilter, "public.ghost has no change of yours in this scope"), &ae)
	require.Equal(t, guidance.ReasonScopeFilter, ae.Reason)
	require.Equal(t, "the revert filter names work that is not yours, nothing was prepared: public.ghost has no change of yours "+
		"in this scope. runs lists only your own runs in the task, and resources only tables you wrote in this scope; run_history "+
		"shows them", ae.Message)

	// A name the store cannot use says nothing of whose work it names: the
	// store's text, without "not yours".
	require.ErrorAs(t, refuse(action.RevertFilterName, "tables are schema.table names"), &ae)
	require.Equal(t, guidance.ReasonScopeFilter, ae.Reason)
	require.Equal(t, "the revert filter is not valid, nothing was prepared: tables are schema.table names", ae.Message)

	require.ErrorAs(t, refuse(action.RevertFilterCap, ""), &ae)
	require.Equal(t, guidance.ReasonScopeFilterCap, ae.Reason)

	var te *toolresult.ToolError
	require.ErrorAs(t, refuse(action.RevertNotOwnRun, ""), &te)
	require.Equal(t, guidance.CodeNotFound, te.Code)
}
