package agent_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

func TestPreviewRevertTool(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	d, h := e.d, e.h
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])
	out, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id IN (61, 62, 63)", "params": []any{"won"},
		"intent": "They signed", "runId": runID,
	})
	require.False(t, isError, "%v", out)
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 62`)

	body, isError := h.call(t, "preview_revert", map[string]any{"runId": runID})
	require.False(t, isError, "%v", body)
	require.Equal(t, "RUN", body["scope"])
	require.Equal(t, runID, body["scopeId"])
	require.EqualValues(t, "2", body["rows"])
	require.EqualValues(t, "1", body["skipped"])
	require.NotContains(t, body, "command", "the person acts on the revert page, never a command")
	list := items(t, body)
	require.Len(t, list, 3)
	conflicts := map[string]int{}
	for _, l := range list {
		require.Equal(t, "UPDATE", l["op"])
		require.Equal(t, "public.leads", l["table"])
		c, _ := l["conflict"].(string)
		conflicts[c]++
	}
	require.Equal(t, map[string]int{"": 2, revert.ConflictChangedAfter: 1}, conflicts)
	require.Equal(t, "won", leadStatus(t, d, 61), "a preview changes nothing")

	first, isError := h.call(t, "preview_revert", map[string]any{"runId": runID, "limit": 2})
	require.False(t, isError, "%v", first)
	require.Len(t, items(t, first), 2)
	next, isError := h.call(t, "preview_revert", map[string]any{"runId": runID, "limit": 2, "cursor": str(t, first["nextCursor"])})
	require.False(t, isError, "%v", next)
	require.Len(t, items(t, next), 1)
	require.NotContains(t, next, "nextCursor")
	require.Equal(t, list[2], items(t, next)[0])
}

func TestPreviewRevertToolErrors(t *testing.T) {
	t.Parallel()
	h := agentHarness(t).h
	id := uuid.Must(uuid.NewV7()).String()
	for _, args := range []map[string]any{
		{},
		{"runId": id, "taskId": id},
		{"runId": id, "sort": "-id"},
		{"runId": "not-a-uuid"},
		{"runId": id, "approve": true},
	} {
		body, isError := h.call(t, "preview_revert", args)
		requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	}
	body, isError := h.call(t, "preview_revert", map[string]any{"runId": id})
	requireToolError(t, body, isError, "NOT_FOUND", "", "")
}

func TestPreviewRevertToolStaleCursor(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	d, h := e.d, e.h
	run, _ := h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	runID := str(t, run["runId"])
	_, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'won' WHERE id IN (64, 65)", "intent": "signed", "runId": runID,
	})
	require.False(t, isError)
	first, _ := h.call(t, "preview_revert", map[string]any{"runId": runID, "limit": 1})
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id IN (64, 65)`)
	body, isError := h.call(t, "preview_revert", map[string]any{"runId": runID, "limit": 1, "cursor": str(t, first["nextCursor"])})
	requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
}

// run_history shows the revert: the run's change names its revert, and
// the agent sees the revert's own record (actor PERSON).
func TestRunHistoryShowsRevert(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	a, h, person := e.a, e.h, e.person
	ctx := context.Background()
	run, _ := h.call(t, "run_start", map[string]any{"intent": "Win a lead"})
	runID := str(t, run["runId"])
	_, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'won' WHERE id = 66", "intent": "signed", "runId": runID,
	})
	require.False(t, isError)

	prep, err := guard.PrepareRevert(ctx, a.Conn, guardmodel.RevertScope{Kind: revert.ScopeRun, ID: uuid.MustParse(runID)}, "Undo")
	require.NoError(t, err)
	as, err := person.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	require.NoError(t, err)

	hist, isError := h.call(t, "run_history", map[string]any{"runId": runID})
	require.False(t, isError, "%v", hist)
	recs := items(t, hist)
	require.Len(t, recs, 1)
	require.Equal(t, "REVERTED", recs[0]["status"])
	require.Equal(t, []any{applied.ChangeID.String()}, recs[0]["revertedBy"])

	body, isError := h.call(t, "preview_revert", map[string]any{"changeId": applied.ChangeID.String()})
	require.False(t, isError, "%v", body)
	require.EqualValues(t, "1", body["rows"], "a revert can be reverted")
}
