package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// filterEnv is an agent "bot" that wrote leads and lead_owner in two runs
// of one task, and an agent "other" that wrote leads and payroll in a run
// of the same task.
type filterEnv struct {
	agentEnv
	taskID, run1, run2 string
	otherRun           uuid.UUID
}

func filterHarness(t *testing.T) filterEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	tables := []string{"public.leads", "public.lead_owner", "public.payroll"}
	bot := d.NewAgent(t, "bot", tables[:2], tables[:2])
	other := d.NewAgent(t, "other", tables, tables)
	env := filterEnv{agentEnv: agentHarnessFor(t, d, bot)}

	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	env.run1, env.taskID = str(t, run["runId"]), str(t, run["taskId"])
	env.write(t, env.run1, "UPDATE public.leads SET status = 'won' WHERE id = 91")
	env.write(t, env.run1, "UPDATE public.lead_owner SET owner = 'bot' WHERE id = 1")
	run, isError = env.h.call(t, "run_start", map[string]any{"intent": "Win more leads", "taskId": env.taskID})
	require.False(t, isError, "%v", run)
	env.run2 = str(t, run["runId"])
	env.write(t, env.run2, "UPDATE public.leads SET status = 'won' WHERE id = 92")

	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: uuid.MustParse(env.taskID), Text: "Same task, other agent"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in,
		`UPDATE public.leads SET status = 'lost' WHERE id = 95`, `INSERT INTO public.payroll VALUES (1, 10)`))
	env.otherRun = in.RunID
	return env
}

func (e filterEnv) write(t *testing.T, runID, sql string) {
	t.Helper()
	out, isError := e.h.call(t, "write", map[string]any{"sql": sql, "intent": "They signed", "runId": runID})
	require.False(t, isError, "%v", out)
}

// call calls tool with args, adding an intent for request_revert.
func (e filterEnv) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	if tool == "request_revert" {
		args["intent"] = "Undo the lead wins"
	}
	return e.h.call(t, tool, args)
}

func tablesOf(t *testing.T, body map[string]any) []string {
	t.Helper()
	list := items(t, body)
	out := make([]string, 0, len(list))
	for _, l := range list {
		out = append(out, str(t, l["table"]))
	}
	return out
}

func revertCount(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	return n
}

// The runs and tables filters narrow the agent's own proposal (RS-1): a
// table of a run, some of its runs in a task, or both; the binding the
// person signs carries them as the proposal.
func TestRevertFiltersNarrowTheProposal(t *testing.T) {
	t.Parallel()
	env := filterHarness(t)

	body, isError := env.call(t, "preview_revert", map[string]any{"runId": env.run1, "tables": []any{"public.lead_owner"}})
	require.False(t, isError, "%v", body)
	require.EqualValues(t, "1", body["rows"])
	require.Equal(t, []string{"public.lead_owner"}, tablesOf(t, body), "only the lead_owner line of run 1")

	body, isError = env.call(t, "preview_revert", map[string]any{"taskId": env.taskID})
	require.False(t, isError, "%v", body)
	require.EqualValues(t, "3", body["rows"], "every own line of the task: leads 91 and 92, lead_owner 1")

	body, isError = env.call(t, "preview_revert", map[string]any{"taskId": env.taskID, "runs": []any{env.run2}})
	require.False(t, isError, "%v", body)
	require.EqualValues(t, "1", body["rows"], "only run 2's lead 92")
	require.Equal(t, []string{"public.leads"}, tablesOf(t, body))
	require.Contains(t, fmt.Sprint(items(t, body)[0]["key"]), "92")

	body, isError = env.call(t, "preview_revert", map[string]any{
		"taskId": env.taskID, "runs": []any{env.run1}, "tables": []any{"public.leads"},
	})
	require.False(t, isError, "%v", body)
	require.EqualValues(t, "1", body["rows"], "only run 1's lead 91")
	require.Equal(t, []string{"public.leads"}, tablesOf(t, body))
	steps, ok := body["nextSteps"].([]any)
	require.True(t, ok, "%v", body)
	step, ok := steps[1].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "request_revert", step["tool"])
	require.Equal(t, map[string]any{"taskId": env.taskID, "runs": []any{env.run1}, "tables": []any{"public.leads"}}, step["arguments"],
		"the request the steps lead to is the one previewed, filters included")
	msg := str(t, body["personMessage"])
	require.Contains(t, msg, "task "+env.taskID+", only 1 of its runs and table public·leads would restore 1 rows", msg)
	require.NotContains(t, msg, "basalt ", "the person runs no command")

	for _, tc := range []struct {
		args    map[string]any
		scope   revert.Scope
		runs    []uuid.UUID
		tables  []string
		message string
	}{
		{
			map[string]any{"runId": env.run1, "tables": []any{"public.lead_owner"}},
			revert.ScopeRun, nil,
			[]string{"public.lead_owner"},
			"Revert of run " + env.run1 + ", only table public·lead_owner: 1 rows to restore",
		},
		{
			map[string]any{"taskId": env.taskID, "runs": []any{env.run2}},
			revert.ScopeTask,
			[]uuid.UUID{uuid.MustParse(env.run2)},
			nil,
			"Revert of task " + env.taskID + ", only 1 of its runs: 1 rows to restore",
		},
	} {
		body, isError := env.call(t, "request_revert", tc.args)
		require.False(t, isError, "%v", body)
		require.Equal(t, "PENDING", body["status"])
		require.EqualValues(t, "1", body["rows"])
		link := str(t, body["revertUrl"])
		_, b, err := revert.ParseRequest(link[strings.Index(link, "#")+1:])
		require.NoError(t, err)
		require.Equal(t, tc.scope, b.Select.Scope)
		require.Equal(t, []string{env.a.Role}, b.Select.Agents)
		require.Equal(t, tc.runs, b.Select.Runs, "the page shows the agent's runs filter as its proposal")
		require.Equal(t, tc.tables, b.Select.Tables, "the page shows the agent's tables filter as its proposal")
		require.Nil(t, b.Proposed, "a proposal nobody rescoped carries no separate proposed")
		require.True(t, strings.HasPrefix(str(t, body["personMessage"]), tc.message), "the chat names the filters as the page does: %s", body["personMessage"])
	}
	require.Equal(t, "won", leadStatus(t, env.d, 91), "a request reverts nothing")

	// A filter that leaves no line is NOTHING_TO_REVERT (AE-8).
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Look only", "taskId": env.taskID})
	require.False(t, isError, "%v", run)
	read, isError := env.h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads WHERE id = 93", "runId": run["runId"]})
	require.False(t, isError, "%v", read)
	body, isError = env.call(t, "request_revert", map[string]any{"taskId": env.taskID, "runs": []any{run["runId"]}})
	requireToolError(t, body, isError, "NOTHING_TO_REVERT", "", "")
}

// More than 20 runs or tables is SCOPE_FILTER_CAP (owner, Q10); 20 is
// within the cap.
func TestRevertFiltersCap(t *testing.T) {
	t.Parallel()
	env := filterHarness(t)
	ids := func(n int) []any {
		out := make([]any, 0, n)
		out = append(out, env.run1)
		for len(out) < n {
			out = append(out, uuid.Must(uuid.NewV7()).String())
		}
		return out
	}
	names := func(n int) []any {
		out := make([]any, 0, n)
		out = append(out, "public.leads")
		for i := 1; i < n; i++ {
			out = append(out, fmt.Sprintf("public.t%d", i))
		}
		return out
	}
	for _, tool := range []string{"preview_revert", "request_revert"} {
		for _, args := range []map[string]any{
			{"taskId": env.taskID, "runs": ids(revert.MaxFilter + 1)},
			{"taskId": env.taskID, "tables": names(revert.MaxFilter + 1)},
			{"runId": env.run1, "tables": names(revert.MaxFilter + 1)},
		} {
			body, isError := env.call(t, tool, args)
			steps := requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "SCOPE_FILTER_CAP")
			require.Equal(t, tool, steps[0]["tool"])
			require.Contains(t, str(t, body["message"]), "at most 20 entries")
		}
		for _, args := range []map[string]any{
			{"taskId": env.taskID, "runs": ids(revert.MaxFilter)},
			{"taskId": env.taskID, "tables": names(revert.MaxFilter)},
		} {
			body, isError := env.call(t, tool, args)
			requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "SCOPE_FILTER")
			msg := str(t, body["message"])
			require.Equal(t, revert.MaxFilter-1, strings.Count(msg, "not one of your runs")+strings.Count(msg, "has no change of yours"),
				"20 entries pass the cap; the 19 that are not the agent's are each named: %s", msg)
		}
	}
	require.Zero(t, revertCount(t, env.d), "nothing was prepared")
}

// runs goes only with taskId: with a change or a run it is SCOPE_FILTER,
// and the wait form takes no filter at all.
func TestRevertRunsFilterNeedsATask(t *testing.T) {
	t.Parallel()
	env := filterHarness(t)
	var changeID string
	require.NoError(t, env.d.Admin.QueryRow(context.Background(),
		`SELECT change_id::text FROM basalt_meta.changes WHERE run_id = $1 LIMIT 1`, env.run1).Scan(&changeID))
	for _, tool := range []string{"preview_revert", "request_revert"} {
		for _, args := range []map[string]any{
			{"runId": env.run1, "runs": []any{env.run1}},
			{"changeId": changeID, "runs": []any{env.run1}},
		} {
			body, isError := env.call(t, tool, args)
			requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "SCOPE_FILTER")
			require.Contains(t, str(t, body["message"]), "runs goes only with taskId")
		}
		for _, args := range []map[string]any{
			{"taskId": env.taskID, "runs": []any{}},
			{"taskId": env.taskID, "tables": []any{}},
			{"taskId": env.taskID, "tables": []any{"leads"}},
			{"taskId": env.taskID, "tables": []any{"public.leads;drop"}},
			{"taskId": env.taskID, "runs": []any{"not-a-uuid"}},
			{"taskId": env.taskID, "runs": []any{env.run1, env.run1}},
		} {
			body, isError := env.call(t, tool, args)
			requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")
		}
	}
	id := uuid.Must(uuid.NewV7()).String()
	for _, args := range []map[string]any{
		{"revertId": id, "tables": []any{"public.leads"}},
		{"revertId": id, "runs": []any{env.run1}},
	} {
		body, isError := env.h.call(t, "request_revert", args)
		requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")
	}
	require.Zero(t, revertCount(t, env.d), "nothing was prepared")
}

// A filter entry outside the agent's own work reads the same whatever it
// is (RS-1): an unknown run, another agent's run in the task and the
// agent's own run in another task; an unknown table, an unguarded table,
// another agent's table and a table the agent wrote in another run.
// Only the entry itself differs, so the filter cannot probe which runs or
// guarded tables exist.
func TestRevertFilterRefusalsReadAlike(t *testing.T) {
	t.Parallel()
	env := filterHarness(t)
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Another task"})
	require.False(t, isError, "%v", run)
	ownElsewhere := str(t, run["runId"])
	env.write(t, ownElsewhere, "UPDATE public.leads SET status = 'won' WHERE id = 94")

	for _, tool := range []string{"preview_revert", "request_revert"} {
		texts := map[string]string{}
		for name, id := range map[string]string{
			"unknown run":          uuid.Must(uuid.NewV7()).String(),
			"another agent's run":  env.otherRun.String(),
			"own run outside task": ownElsewhere,
		} {
			body, isError := env.call(t, tool, map[string]any{"taskId": env.taskID, "runs": []any{id}})
			steps := requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "SCOPE_FILTER")
			require.Equal(t, "list_runs", steps[1]["tool"], "%s: a task's runs are in list_runs", name)
			require.Contains(t, str(t, body["message"]), "run "+id+" is not one of your runs in task "+env.taskID)
			texts[name] = refusalText(t, body, id)
		}
		requireAlike(t, tool, texts)

		texts = map[string]string{}
		for name, table := range map[string]string{
			"unknown table":           "public.ghost",
			"unguarded table":         "public.note_tags",
			"another agent's table":   "public.payroll",
			"own table outside scope": "public.lead_owner",
		} {
			body, isError := env.call(t, tool, map[string]any{"runId": env.run2, "tables": []any{table}})
			steps := requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "SCOPE_FILTER")
			require.Equal(t, "run_history", steps[1]["tool"], "%s: a run's tables are in its history", name)
			require.Contains(t, str(t, body["message"]), table+" has no change of yours in this scope")
			texts[name] = refusalText(t, body, table)
		}
		requireAlike(t, tool, texts)
	}
	require.Zero(t, revertCount(t, env.d), "nothing was prepared")
}

// refusalText is the whole error body as JSON with entry replaced.
func refusalText(t *testing.T, body map[string]any, entry string) string {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return strings.ReplaceAll(string(raw), entry, "<entry>")
}

func requireAlike(t *testing.T, tool string, texts map[string]string) {
	t.Helper()
	var first, firstName string
	for name, text := range texts {
		if first == "" {
			first, firstName = text, name
			continue
		}
		require.Equal(t, first, text, "%s: %s and %s read alike", tool, firstName, name)
	}
}
