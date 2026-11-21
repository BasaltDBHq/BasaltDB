package agent

import (
	"errors"
	"strings"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/action"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
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

	msg, steps, err := serviceFor(t, "linux", "").previewGuidance(RevertPreview{Scope: scope, Rows: 2})
	require.NoError(t, err)
	require.Equal(t, scopeArgs(scope), steps[1].Arguments, "the request the person agrees to is the one previewed")
	require.Contains(t, msg, "task "+caseRunID+", only 1 of its runs and tables public·leads and 1 more would restore")
	require.NotContains(t, msg, "basalt ", "the person runs no command")

	r := revertOf(t, "Undo", []string{changedAfterLine}, false)
	r.BindingText = strings.Replace(r.BindingText, `"tables": null`, `"tables": ["public.lead_owner"]`, 1)
	want := map[string]any{"runId": caseRunID, "tables": []string{"public.lead_owner"}}
	require.Equal(t, want, expiredSteps(r)[1].Arguments)
	var te *mcp.ToolError
	require.True(t, errors.As(serviceFor(t, "linux", "").rowsChanged(r, "rows changed since"), &te))
	require.Equal(t, want, te.NextSteps[0].Arguments)
	require.Contains(t, te.PersonMessage, "run "+caseRunID+", only table public·lead_owner, so nothing was reverted")

	r.BindingText = ""
	require.Equal(t, map[string]any{"runId": caseRunID}, expiredSteps(r)[1].Arguments, "a widened revert's binding is hidden")
}
