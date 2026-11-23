package agent_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

var leads = []string{"public.leads"}

// guarded is a test database with the guard installed, the demo schema,
// and an agent "bot" that can read and write public.leads only.
func guarded(t *testing.T) (*guardtest.DB, harness) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	return d, newHarness(t, a.URL, sqlguard.DefaultLimits())
}

func str(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	require.True(t, ok, "%v is not a string", v)
	return s
}

func items(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["items"].([]any)
	require.True(t, ok, "%v", body)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		require.True(t, ok)
		out = append(out, m)
	}
	return out
}

func (h harness) history(t *testing.T, runID string) []map[string]any {
	t.Helper()
	body, isError := h.call(t, "run_history", map[string]any{"runId": runID})
	require.False(t, isError, "%v", body)
	return items(t, body)
}

func leadStatus(t *testing.T, d *guardtest.DB, id int) string {
	t.Helper()
	var s string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT status FROM public.leads WHERE id = $1`, id).Scan(&s))
	return s
}

func TestWriteThroughTheGuard(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)

	run, isError := h.call(t, "run_start", map[string]any{"intent": "Merge duplicate leads from yesterday"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])
	require.NotEmpty(t, str(t, run["taskId"]))

	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"merged", 4},
		"intent": "Lead 4 duplicates lead 3", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, "UPDATE", body["op"])
	require.Equal(t, json.Number("1"), body["rows"])
	require.Equal(t, runID, body["runId"])
	changeID := str(t, body["changeId"])
	require.Equal(t, "merged", leadStatus(t, d, 4))

	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = score + 1 WHERE id = 5 RETURNING id, score", "intent": "Bump lead 5", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, []any{map[string]any{"id": json.Number("5"), "score": json.Number("6")}}, body["returning"])

	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'x' WHERE id = -1", "intent": "Touch nothing", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, json.Number("0"), body["rows"], "a zero-row write is still a recorded change")

	recs := h.history(t, runID)
	require.Len(t, recs, 3)
	first := recs[2] // newest first
	require.Equal(t, changeID, first["changeId"])
	require.Equal(t, "APPLIED", first["status"])
	require.Equal(t, "Lead 4 duplicates lead 3", first["intent"])
	require.Equal(t, "UPDATE leads SET status = $1 WHERE id = $2", first["statement"])
	actor, ok := first["actor"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "AGENT", actor["kind"])
	require.Equal(t, runID, actor["runId"])
	rows, ok := first["rowChanges"].([]any)
	require.True(t, ok)
	require.Len(t, rows, 1)
	row, ok := rows[0].(map[string]any)
	require.True(t, ok)
	before, ok := row["before"].(map[string]any)
	require.True(t, ok)
	after, ok := row["after"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "open", before["status"])
	require.Equal(t, "merged", after["status"])

	page, isError := h.call(t, "run_history", map[string]any{"runId": runID, "limit": 2})
	require.False(t, isError, "%v", page)
	require.Len(t, items(t, page), 2)
	next, isError := h.call(t, "run_history", map[string]any{"runId": runID, "limit": 2, "cursor": str(t, page["nextCursor"])})
	require.False(t, isError, "%v", next)
	require.Len(t, items(t, next), 1)
	require.Nil(t, next["nextCursor"], "no cursor on the last page")
}

func TestWriteWithoutARunStartsOne(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	body, isError := h.call(t, "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id = 7", "intent": "Reset lead 7"})
	require.False(t, isError, "%v", body)
	recs := h.history(t, str(t, body["runId"]))
	require.Len(t, recs, 1)
	require.Equal(t, "Reset lead 7", recs[0]["intent"])
}

func TestRunsShareATask(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	first, isError := h.call(t, "run_start", map[string]any{"intent": "Clean up leads"})
	require.False(t, isError, "%v", first)
	second, isError := h.call(t, "run_start", map[string]any{"intent": "Clean up leads, part two", "taskId": first["taskId"]})
	require.False(t, isError, "%v", second)
	require.Equal(t, first["taskId"], second["taskId"])
	require.NotEqual(t, first["runId"], second["runId"])
}

func TestWriteRefusalsAreRecorded(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Try things the policy refuses"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])

	cases := []struct {
		name, sql              string
		code, reason, sqlState string
		op                     string
	}{
		{"delete is held", "DELETE FROM leads WHERE id = 1", agent.CodeApprovalRequired, "", "", "DELETE"},
		{"11 rows are held", "UPDATE leads SET score = 0 WHERE id BETWEEN 10 AND 20", agent.CodeApprovalRequired, "", "", "UPDATE"},
		{"over 50 rows", "UPDATE leads SET score = 0 WHERE id <= 60", agent.CodeRowLimitExceeded, "", "BS003", "UPDATE"},
		{"ddl", "DROP TABLE leads", agent.CodeStatementRefused, "DDL_NOT_ALLOWED", "", "OTHER"},
		{"read sent to write", "SELECT * FROM leads", agent.CodeStatementRefused, "WRONG_TOOL", "", "SELECT"},
		{"function", "UPDATE leads SET name = pg_sleep(1)::text WHERE id = 1", agent.CodeStatementRefused, "FUNCTION_NOT_ALLOWED", "", "UPDATE"},
		{"ungranted table", "UPDATE payroll SET amount = 0 WHERE id = 1", agent.CodePermissionDenied, "", "42501", "UPDATE"},
		{"constraint", "INSERT INTO leads (id, name) VALUES (1, 'dup')", agent.CodeSQLError, "", "23505", "INSERT"},
	}
	for _, c := range cases {
		body, isError := h.call(t, "write", map[string]any{"sql": c.sql, "intent": "test " + c.name, "runId": runID})
		requireToolError(t, body, isError, c.code, c.reason, c.sqlState)
	}
	require.Equal(t, "open", leadStatus(t, d, 1))

	recs := h.history(t, runID)
	require.Len(t, recs, len(cases))
	for i, c := range cases {
		rec := recs[len(cases)-1-i]
		require.Equal(t, c.op, rec["op"], c.name)
		require.Equal(t, "test "+c.name, rec["intent"], c.name)
		if c.code == agent.CodeApprovalRequired {
			require.Equal(t, "APPROVAL_PENDING", rec["status"], c.name) // held, not refused (M2)
			continue
		}
		require.Equal(t, "REFUSED", rec["status"], c.name)
		reason, ok := rec["reason"].(map[string]any)
		require.True(t, ok, c.name)
		require.Equal(t, c.code, reason["code"], c.name)
	}
}

func TestWriteArgumentErrors(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	cases := []struct {
		name string
		tool string
		args map[string]any
		code string
	}{
		{"no intent", "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id = 1"}, agent.CodeIntentRequired},
		{"empty intent", "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id = 1", "intent": ""}, agent.CodeIntentRequired},
		{"unknown run", "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id = 1", "intent": "x", "runId": "0193a4c2-0000-7000-8000-000000000001"}, agent.CodeNotFound},
		{"unknown argument", "write", map[string]any{"sql": "UPDATE leads SET score = 1", "intent": "x", "dryRun": true}, agent.CodeInvalidArgument},
		{"params mismatch", "write", map[string]any{"sql": "UPDATE leads SET score = $1 WHERE id = $2", "intent": "x", "params": []any{1}}, agent.CodeInvalidArgument},
		{"run_start without intent", "run_start", map[string]any{}, agent.CodeInvalidArgument},
		{"run_start bad task", "run_start", map[string]any{"intent": "x", "taskId": "task_91c"}, agent.CodeInvalidArgument},
		{"history of unknown run", "run_history", map[string]any{"runId": "0193a4c2-0000-7000-8000-000000000001"}, agent.CodeNotFound},
		{"history without run", "run_history", map[string]any{}, agent.CodeInvalidArgument},
		{"history bad sort", "run_history", map[string]any{"runId": "0193a4c2-0000-7000-8000-000000000001", "sort": "at"}, agent.CodeNotFound},
		{"query of unknown run", "query", map[string]any{"sql": "SELECT 1", "runId": "0193a4c2-0000-7000-8000-000000000001"}, agent.CodeNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, isError := h.call(t, c.tool, c.args)
			requireToolError(t, body, isError, c.code, "", "")
		})
	}
}

func TestHistoryBadSortOnARealRun(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	run, isError := h.call(t, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "%v", run)
	body, isError := h.call(t, "run_history", map[string]any{"runId": run["runId"], "sort": "at"})
	requireToolError(t, body, isError, agent.CodeInvalidArgument, "", "")
}

func TestQueryRefusalInARunIsRecorded(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Read leads"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])

	body, isError := h.call(t, "query", map[string]any{"sql": "SELECT count(id) AS n FROM leads", "runId": runID})
	require.False(t, isError, "%v", body)
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT pg_sleep(5)", "runId": runID})
	requireToolError(t, body, isError, agent.CodeStatementRefused, "FUNCTION_NOT_ALLOWED", "")

	recs := h.history(t, runID)
	require.Len(t, recs, 2, "the read and the refusal")
	require.Equal(t, "REFUSED", recs[0]["status"])
	require.Equal(t, "SELECT", recs[0]["op"])
	require.Equal(t, "Read leads", recs[0]["intent"])
	require.Equal(t, "APPLIED", recs[1]["status"])
	require.Equal(t, "SELECT", recs[1]["op"])
	require.Equal(t, json.Number("1"), recs[1]["rows"])
}

func TestAnotherAgentsRunIsNotFound(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	bot := newHarness(t, d.NewAgent(t, "bot", leads, leads).URL, sqlguard.DefaultLimits())
	other := newHarness(t, d.NewAgent(t, "other", leads, leads).URL, sqlguard.DefaultLimits())

	run, isError := bot.call(t, "run_start", map[string]any{"intent": "Bot's own run"})
	require.False(t, isError, "%v", run)
	body, isError := other.call(t, "run_history", map[string]any{"runId": run["runId"]})
	requireToolError(t, body, isError, agent.CodeNotFound, "", "")
	body, isError = other.call(t, "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id = 2", "intent": "x", "runId": run["runId"]})
	requireToolError(t, body, isError, agent.CodeNotFound, "", "")
}
