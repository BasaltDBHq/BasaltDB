package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// requireCatalogSteps checks an error body of tool against the catalog's
// entry for its code and reason, and returns its steps.
func requireCatalogSteps(t *testing.T, body map[string]any, isError bool, tool, code, reason string) []map[string]any {
	t.Helper()
	requireToolError(t, body, isError, code, reason, "")
	if reason == "" {
		require.NotContains(t, body, "reason", "%v", body)
	}
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	e, ok := c.ErrorEntry(code, reason, tool)
	require.True(t, ok, "%s %s %s", code, reason, tool)
	return requireSteps(t, body, e.Steps, e.PersonMessage)
}

// stepArgs is a step's arguments as a tool call.
func stepArgs(t *testing.T, step map[string]any) map[string]any {
	t.Helper()
	args, ok := step["arguments"].(map[string]any)
	require.True(t, ok, "%v", step)
	return args
}

// The guard's and the statement filter's refusals, on a real database as the
// agent role, each answer with the catalog's steps, and the steps the engine
// fills in work when the agent follows them.
func TestErrorsFromARealGuardCarryTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	runID := h.startRun(t, "Close leads nobody answered")

	// INTENT_REQUIRED: the one step revises the write.
	body, isError := h.call(t, "write", map[string]any{"sql": "UPDATE leads SET status = 'x' WHERE id = 1", "runId": runID})
	steps := requireCatalogSteps(t, body, isError, "write", "INTENT_REQUIRED", "")
	require.Equal(t, "write", steps[0]["tool"])

	// STATEMENT_REFUSED, with and without the person.
	body, isError = h.call(t, "query", map[string]any{"sql": "SELEC id FROM leads", "runId": runID})
	requireCatalogSteps(t, body, isError, "query", "STATEMENT_REFUSED", "PARSE_ERROR")
	body, isError = h.call(t, "write", map[string]any{"sql": "DROP TABLE leads", "intent": "Tidy up", "runId": runID})
	requireCatalogSteps(t, body, isError, "write", "STATEMENT_REFUSED", "DDL_NOT_ALLOWED")

	// SQL_ERROR and PERMISSION_DENIED.
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT nope FROM leads", "runId": runID})
	requireCatalogSteps(t, body, isError, "query", "SQL_ERROR", "")
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT amount FROM payroll", "runId": runID})
	steps = requireCatalogSteps(t, body, isError, "query", "PERMISSION_DENIED", "")
	require.Contains(t, str(t, steps[2]["command"]), "--dry-run", "Postgres names the table without its schema: the person sees the plan")

	// STALE_READ: the first step is the query that reads the row again;
	// following it and then the write goes through.
	h.mustQuery(t, map[string]any{"sql": "SELECT id, status FROM leads WHERE id = $1", "params": []any{42}, "runId": runID})
	d.Exec(t, `UPDATE public.leads SET status = 'won' WHERE id = 42`)
	write := map[string]any{"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"lost", 42}, "intent": "No answer", "runId": runID}
	body, isError = h.call(t, "write", write)
	steps = requireCatalogSteps(t, body, isError, "write", "STALE_READ", "")
	require.Equal(t, "query", steps[0]["tool"])
	read, isError := h.call(t, "query", stepArgs(t, steps[0]))
	require.False(t, isError, "the step's query runs as given: %v", read)
	require.Len(t, read["rows"], 1)
	body, isError = h.call(t, "write", write)
	require.False(t, isError, "after reading the row again the write is based on what the agent saw: %v", body)
}

// ROW_LIMIT_EXCEEDED, as the agent role: the steps stop, ask, and only then
// offer batches of the most a hold takes, and a batch of that size is held
// for approval, never applied (AE-7, security).
func TestRowLimitStepsNeverOfferABatchBelowAHold(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	h := env.h
	runID := h.startRun(t, "Bump every lead")

	body, isError := h.call(t, "write", map[string]any{"sql": "UPDATE leads SET score = score + 1", "intent": "Bump", "runId": runID})
	steps := requireCatalogSteps(t, body, isError, "write", "ROW_LIMIT_EXCEEDED", "")
	require.Equal(t, "STOP", steps[0]["action"])
	require.Equal(t, "ASK_PERSON", steps[1]["action"])
	retry := steps[2]
	require.Equal(t, "RETRY_SMALLER_BATCHES", retry["action"])
	require.Contains(t, str(t, retry["text"]), "only on an explicit yes")
	batch, err := retry["maxRows"].(json.Number).Int64()
	require.NoError(t, err)
	require.EqualValues(t, agent.MaxRetryRows, batch)
	var scoreSum int
	require.NoError(t, env.d.Admin.QueryRow(context.Background(), `SELECT sum(score)::int FROM public.leads`).Scan(&scoreSum))

	// What the guard holds is any write of more than 10 rows or any delete,
	// so a batch of the offered size is held and nothing is applied.
	body, isError = h.call(t, "write", map[string]any{
		"sql": fmt.Sprintf("UPDATE leads SET score = score + 1 WHERE id <= %d", batch), "intent": "Bump the first batch", "runId": runID,
	})
	requireCatalogSteps(t, body, isError, "write", "APPROVAL_REQUIRED", "HELD_NO_PAGES")
	var after int
	require.NoError(t, env.d.Admin.QueryRow(context.Background(), `SELECT sum(score)::int FROM public.leads`).Scan(&after))
	require.Equal(t, scoreSum, after, "neither the refused write nor the held batch changed a row")
}

// A held write's steps carry the link and the repeat of the write; the repeat
// before the person approved is NOT_SIGNED, with the link again.
func TestHeldWriteStepsCarryTheLinkAndTheRepeat(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	runID := env.h.startRun(t, "Remove a lead")
	write := map[string]any{"sql": "DELETE FROM leads WHERE id = 150", "intent": "Duplicate", "runId": runID}

	body, isError := env.h.call(t, "write", write)
	steps := requireCatalogSteps(t, body, isError, "write", "APPROVAL_REQUIRED", "HELD")
	approval := approvalOf(t, body)
	require.Equal(t, approval["approvalUrl"], steps[0]["url"])
	require.Nil(t, steps[0]["command"], "the step is the link alone")
	require.Equal(t, true, steps[1]["repeatCall"])
	require.Equal(t, map[string]any{"approvalId": approval["approvalId"]}, stepArgs(t, steps[1]))
	require.Equal(t, approval["personMessage"], body["personMessage"])

	again := map[string]any{"waitForApproval": 0}
	for k, v := range write {
		again[k] = v
	}
	again["approvalId"] = approval["approvalId"]
	body, isError = env.h.call(t, "write", again)
	steps = requireCatalogSteps(t, body, isError, "write", "APPROVAL_INVALID", "NOT_SIGNED")
	require.Nil(t, steps[0]["command"], "the person opens the link they were given, no command")
}

// The redo (AE-14): the person reverted the agent's run; preview_revert says
// so and names the revert's change; request_revert of that change is the
// agent's own, the person signs, the agent's values are back and a row a
// person changed after the revert is skipped. Another agent's revert stays
// NOT_FOUND.
func TestRedoARevertedRun(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	ctx := context.Background()
	runID, _ := winLeads(t, env.h, "91, 92")
	prep, err := guard.PrepareRevert(ctx, env.a.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: uuid.MustParse(runID)}, "Undo")
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, env.a.Conn, prep.RevertID, signBinding(t, env.person, prep.BindingText))
	require.NoError(t, err)
	require.Equal(t, "open", leadStatus(t, env.d, 91))
	revertChange := revertedChange(t, env, runID)
	require.NotEmpty(t, revertChange)
	require.Equal(t, applied.ChangeID.String(), revertChange)
	env.d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 92`) // a person, after the revert

	body, isError := env.h.call(t, "preview_revert", map[string]any{"runId": runID})
	steps := requireCatalogSteps(t, body, isError, "preview_revert", "NOTHING_TO_REVERT", "ALREADY_REVERTED")
	require.Contains(t, str(t, body["personMessage"]), revertChange, "the message names the revert's change")
	require.Equal(t, map[string]any{"changeId": revertChange}, stepArgs(t, steps[1]), "so does the step that redoes it")

	args := stepArgs(t, steps[1])
	args["intent"] = "Undo the undo: the agent's work stands"
	req := requestRevert(t, env.h, args)
	require.Equal(t, "CHANGE", req["scope"])
	require.Equal(t, revertChange, req["scopeId"])
	done := requestRevert(t, env.h, map[string]any{"revertId": req["revertId"], "signature": personCode(t, env, str(t, req["revertUrl"]))})
	require.Equal(t, "APPLIED", done["status"])
	require.Equal(t, "won", leadStatus(t, env.d, 91), "the agent's values are back")
	require.Equal(t, "person", leadStatus(t, env.d, 92), "the person's later change is skipped")

	// Another agent's revert is not this agent's.
	other := env.d.NewAgent(t, "other", leads, leads)
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Other's work"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 93`))
	otherPrep, err := guard.PrepareRevert(ctx, other.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo")
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, other.Conn, otherPrep.RevertID, signBinding(t, env.person, otherPrep.BindingText))
	require.NoError(t, err)
	var otherRevertChange string
	require.NoError(t, env.d.Admin.QueryRow(ctx,
		`SELECT unnest(reverted_by)::text FROM basalt_meta.changes WHERE run_id = $1`, in.RunID).Scan(&otherRevertChange))
	body, isError = env.h.call(t, "request_revert", map[string]any{"changeId": otherRevertChange, "intent": "Undo"})
	requireErrorSteps(t, body, isError, "NOT_FOUND", "CHANGE")
}
