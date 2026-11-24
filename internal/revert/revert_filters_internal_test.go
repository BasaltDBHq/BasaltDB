package revert

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// A request made from the steps keeps the filters the person was shown:
// the preview's REVISE_CALL, and requesting an expired or changed revert
// again, carry runs and tables.
func TestRevertStepsKeepTheFilters(t *testing.T) {
	t.Parallel()
	run := uuid.MustParse(caseRunID)
	scope := action.Scope{Kind: revert.ScopeTask, ID: run, Runs: []uuid.UUID{run}, Tables: []string{"public.leads", "public.lead_owner"}}
	require.Equal(t, map[string]any{"taskId": caseRunID, "runs": []string{caseRunID}, "tables": []string{"public.leads", "public.lead_owner"}},
		scopeArgs(scope))
	require.Equal(t, map[string]any{"runId": caseRunID}, scopeArgs(action.Scope{Kind: revert.ScopeRun, ID: run}))

	msg, steps, err := newService(t, "linux", "").previewGuidance(RevertPreview{Scope: scope, Rows: 2})
	require.NoError(t, err)
	require.Equal(t, scopeArgs(scope), steps[1].Arguments, "the request the person agrees to is the one previewed")
	require.Contains(t, msg, "task "+caseRunID+", only 1 of its runs and tables public·leads and 1 more would restore")
	require.NotContains(t, msg, "basalt ", "the person runs no command")

	r := revertOf(t, "Undo", []string{changedAfterLine}, false)
	r.BindingText = strings.Replace(r.BindingText, `"tables": null`, `"tables": ["public.lead_owner"]`, 1)
	want := map[string]any{"runId": caseRunID, "tables": []string{"public.lead_owner"}}
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
	refuse := func(detail, hint string) error {
		return scopeRefused(scope, store.MapError(&pgconn.PgError{Code: "BS011", Message: "SCOPE_REFUSED", Detail: detail, Hint: hint}))
	}

	var ae *guidance.ArgumentError
	require.ErrorAs(t, refuse(guardmodel.ScopeFilter, "public.ghost has no change of yours in this scope"), &ae)
	require.Equal(t, guidance.ReasonScopeFilter, ae.Reason)
	require.Contains(t, ae.Message, "public.ghost has no change of yours in this scope")

	require.ErrorAs(t, refuse(guardmodel.ScopeFilterCap, ""), &ae)
	require.Equal(t, guidance.ReasonScopeFilterCap, ae.Reason)

	var te *toolresult.ToolError
	require.ErrorAs(t, refuse(guardmodel.ScopeNotOwnRun, ""), &te)
	require.Equal(t, guidance.CodeNotFound, te.Code)
}
