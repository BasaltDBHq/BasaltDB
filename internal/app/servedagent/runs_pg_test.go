package servedagent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// listRuns calls list_runs and returns its items and next cursor.
func (h harness) listRuns(t *testing.T, args map[string]any) ([]map[string]any, string) {
	t.Helper()
	body, isError := h.call(t, "list_runs", args)
	require.False(t, isError, "%v", body)
	next, _ := body["nextCursor"].(string)
	return items(t, body), next
}

// runIDs are the runId of each item, in order.
func runIDs(t *testing.T, list []map[string]any) []string {
	t.Helper()
	out := make([]string, 0, len(list))
	for _, r := range list {
		out = append(out, str(t, r["runId"]))
	}
	return out
}

// startRuns starts n runs and returns their ids, oldest first.
func startRuns(t *testing.T, h harness, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := range n {
		ids = append(ids, h.startRun(t, fmt.Sprintf("run %d", i+1)))
	}
	return ids
}

func reversed(ids []string) []string {
	out := make([]string, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		out = append(out, ids[i])
	}
	return out
}

func TestListRunsCountsWhatEachRunDid(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	h := e.h
	ctx := context.Background()
	empty := h.startRun(t, "Nothing yet")
	runID := h.startRun(t, "Tidy the leads")
	write := func(sql string) map[string]any {
		return map[string]any{"sql": sql, "intent": "tidy", "runId": runID}
	}

	for _, sql := range []string{
		"UPDATE leads SET status = 'won' WHERE id = 1",
		"UPDATE leads SET status = 'won' WHERE id IN (2, 3)",
	} {
		body, isError := h.call(t, "write", write(sql))
		require.False(t, isError, "%v", body)
	}
	undo, isError := h.call(t, "write", write("UPDATE leads SET status = 'lost' WHERE id = 66"))
	require.False(t, isError, "%v", undo)
	h.mustQuery(t, map[string]any{"sql": "SELECT id FROM leads WHERE id = 1", "runId": runID})
	body, isError := h.call(t, "write", write("DROP TABLE leads"))
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "DDL_NOT_ALLOWED", "")
	body, isError = h.call(t, "write", write("UPDATE leads SET score = 0 WHERE id BETWEEN 10 AND 25"))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")

	// The person reverts the third write in full.
	prep, err := guard.PrepareRevert(ctx, e.a.Conn,
		action.Scope{Kind: revert.ScopeChange, ID: uuid.MustParse(str(t, undo["changeId"]))}, "Undo lead 66")
	require.NoError(t, err)
	as, err := e.person.Sign(approval.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.a.Conn, prep.RevertID, as)
	require.NoError(t, err)

	list, next := h.listRuns(t, map[string]any{})
	require.Empty(t, next)
	require.Equal(t, []string{runID, empty}, runIDs(t, list), "newest first")
	run := list[0]
	require.Equal(t, "Tidy the leads", run["intent"])
	require.NotEmpty(t, str(t, run["taskId"]))
	_, err = time.Parse(time.RFC3339, str(t, run["startedAt"]))
	require.NoError(t, err)
	_, err = time.Parse(time.RFC3339, str(t, run["lastChangeAt"]))
	require.NoError(t, err)
	for field, want := range map[string]string{
		"applied": "2", "held": "1", "refused": "1", "reverted": "1", "reads": "1", "rowsWritten": "4",
	} {
		require.Equal(t, json.Number(want), run[field], field)
	}
	require.Equal(t, []any{"public.leads"}, run["tables"])
	require.NotContains(t, run, "tablesTruncated")

	none := list[1]
	require.NotContains(t, none, "lastChangeAt", "a run with no change record")
	require.Equal(t, []any{}, none["tables"])
	for _, field := range []string{"applied", "held", "refused", "reverted", "reads", "rowsWritten"} {
		require.Equal(t, json.Number("0"), none[field], field)
	}
}

func TestListRunsPagesBothWays(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	ids := startRuns(t, h, 5)

	for _, c := range []struct {
		sort string
		want []string
	}{
		{"", reversed(ids)},
		{"-id", reversed(ids)},
		{"id", ids},
	} {
		args := map[string]any{"limit": 2}
		if c.sort != "" {
			args["sort"] = c.sort
		}
		var got []string
		var pages int
		for {
			list, next := h.listRuns(t, args)
			got = append(got, runIDs(t, list)...)
			pages++
			if next == "" {
				break
			}
			// The cursor round trips: the same cursor gives the same page.
			again, againNext := h.listRuns(t, map[string]any{"limit": 2, "sort": c.sort, "cursor": next})
			args["cursor"] = next
			list, sameNext := h.listRuns(t, args)
			require.Equal(t, runIDs(t, again), runIDs(t, list), c.sort)
			require.Equal(t, againNext, sameNext, c.sort)
		}
		require.Equal(t, c.want, got, c.sort)
		require.Equal(t, 3, pages, c.sort)
	}

	// The default limit lists them all on one page.
	list, next := h.listRuns(t, map[string]any{})
	require.Len(t, list, len(ids))
	require.Empty(t, next)
}

func TestListRunsTimeRange(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	ids := startRuns(t, h, 3)
	base := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Hour) }
	for i, id := range ids {
		d.Exec(t, `UPDATE basalt_meta.runs SET started_at = $1 WHERE run_id = $2`, at(i), id)
	}
	text := func(i int) string { return at(i).Format(time.RFC3339) }

	for _, c := range []struct {
		name string
		args map[string]any
		want []string
	}{
		{"start is inclusive", map[string]any{"startTime": text(1)}, []string{ids[2], ids[1]}},
		{"end is exclusive", map[string]any{"endTime": text(2)}, []string{ids[1], ids[0]}},
		{"both", map[string]any{"startTime": text(1), "endTime": text(2)}, []string{ids[1]}},
		{"one second wide", map[string]any{"startTime": text(0), "endTime": at(0).Add(time.Second).Format(time.RFC3339)}, []string{ids[0]}},
		{"other offset", map[string]any{"startTime": at(1).In(time.FixedZone("x", 7*3600)).Format(time.RFC3339)}, []string{ids[2], ids[1]}},
		{"nothing in range", map[string]any{"startTime": at(3).Format(time.RFC3339)}, []string{}},
		{"with sort and paging", map[string]any{"startTime": text(0), "sort": "id", "limit": 1}, []string{ids[0]}},
	} {
		list, _ := h.listRuns(t, c.args)
		require.Equal(t, c.want, runIDs(t, list), c.name)
		if c.name != "with sort and paging" {
			continue
		}
		require.Equal(t, text(0), list[0]["startedAt"], c.name)
	}

	for name, args := range map[string]map[string]any{
		"end equals start": {"startTime": text(1), "endTime": text(1)},
		"end before start": {"startTime": text(2), "endTime": text(1)},
		"not RFC 3339":     {"startTime": "yesterday"},
	} {
		body, isError := h.call(t, "list_runs", args)
		requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
		require.NotContains(t, body, "items", name)
	}
}

func TestListRunsArgumentErrors(t *testing.T) {
	t.Parallel()
	_, h := guarded(t)
	startRuns(t, h, 1)
	for name, args := range map[string]map[string]any{
		"unknown argument":   {"agent": "other"},
		"task filter":        {"taskId": uuid.Must(uuid.NewV7()).String()},
		"unknown sort":       {"sort": "startedAt"},
		"cursor not base64":  {"cursor": "%%%"},
		"cursor not a run":   {"cursor": pagination.EncodeIDCursor("not-a-uuid")},
		"limit not a number": {"limit": "ten"},
	} {
		body, isError := h.call(t, "list_runs", args)
		require.True(t, isError, name)
		require.Equal(t, "INVALID_ARGUMENT", body["code"], "%s: %v", name, body)
	}
}

// TestListRunsTablesTruncated: a run names at most 10 tables, in name
// order, and says when it wrote to more.
func TestListRunsTablesTruncated(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	tables := make([]string, 0, 12)
	for i := 12; i >= 1; i-- { // created out of name order
		name := fmt.Sprintf("public.t%02d", i)
		d.Exec(t, fmt.Sprintf(`CREATE TABLE %s (id int PRIMARY KEY)`, name))
		tables = append(tables, name)
	}
	h := newHarness(t, d.NewAgent(t, "bot", tables, tables).URL, sqlguard.DefaultLimits())

	wide := h.startRun(t, "Write to every table")
	for _, table := range tables {
		body, isError := h.call(t, "write", map[string]any{
			"sql": "INSERT INTO " + strings.TrimPrefix(table, "public.") + " (id) VALUES (1)", "intent": "fill", "runId": wide,
		})
		require.False(t, isError, "%v", body)
	}
	narrow := h.startRun(t, "Write to ten tables")
	for i := 1; i <= 10; i++ {
		body, isError := h.call(t, "write", map[string]any{
			"sql": fmt.Sprintf("INSERT INTO t%02d (id) VALUES (2)", i), "intent": "fill", "runId": narrow,
		})
		require.False(t, isError, "%v", body)
	}

	list, _ := h.listRuns(t, map[string]any{})
	require.Equal(t, []string{narrow, wide}, runIDs(t, list))
	want := make([]any, 0, 10)
	for i := 1; i <= 10; i++ {
		want = append(want, fmt.Sprintf("public.t%02d", i))
	}
	require.Equal(t, want, list[0]["tables"])
	require.NotContains(t, list[0], "tablesTruncated", "exactly ten is not truncated")
	require.Equal(t, want, list[1]["tables"])
	require.Equal(t, true, list[1]["tablesTruncated"])
	require.Equal(t, json.Number("12"), list[1]["applied"])
	require.Equal(t, json.Number("12"), list[1]["rowsWritten"])
}

// TestListRunsOwnRunsOnly is the security test: two agent roles on one
// database, each listing through its own credential, see only their own
// runs, and neither can read the runs table under the view.
func TestListRunsOwnRunsOnly(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	botAgent := d.NewAgent(t, "bot", leads, leads)
	otherAgent := d.NewAgent(t, "other", leads, leads)
	bot := newHarness(t, botAgent.URL, sqlguard.DefaultLimits())
	other := newHarness(t, otherAgent.URL, sqlguard.DefaultLimits())

	botRuns := startRuns(t, bot, 3)
	otherRuns := startRuns(t, other, 2)
	body, isError := other.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = 1 WHERE id = 9", "intent": "other's write", "runId": otherRuns[1],
	})
	require.False(t, isError, "%v", body)

	list, _ := bot.listRuns(t, map[string]any{})
	require.Equal(t, reversed(botRuns), runIDs(t, list))
	list, _ = other.listRuns(t, map[string]any{"sort": "id"})
	require.Equal(t, otherRuns, runIDs(t, list))
	require.Equal(t, json.Number("1"), list[1]["applied"])

	// Another agent's cursor only continues within the caller's own runs.
	list, _ = bot.listRuns(t, map[string]any{"cursor": pagination.EncodeIDCursor(otherRuns[0]), "sort": "id"})
	require.NotContains(t, runIDs(t, list), otherRuns[1])

	// As the agent role itself: the view shows its own runs only, and the
	// table under it is closed.
	ctx := context.Background()
	var n int
	require.NoError(t, botAgent.Conn.QueryRow(ctx,
		`SELECT count(run_id) FROM basalt_meta.agent_runs WHERE run_id = ANY($1::uuid[])`, otherRuns).Scan(&n))
	require.Zero(t, n)
	_, err := botAgent.Conn.Exec(ctx, `SELECT run_id FROM basalt_meta.runs`)
	require.ErrorContains(t, err, "permission denied")

	var indexed bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT to_regclass('basalt_meta.runs_agent') IS NOT NULL`).Scan(&indexed))
	require.True(t, indexed, "version 14 indexes runs by agent and id")
}
