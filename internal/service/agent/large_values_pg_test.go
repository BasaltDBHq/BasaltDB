package agent_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// bigValue is over the 1 MiB a value may cost and still be read.
const bigValue = 2000000

// largeValuesStatementTimeout replaces the agent's default statement timeout
// in newLargeEnv.
const largeValuesStatementTimeout = time.Minute

func sum256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// largeEnv is an agent whose run wrote large values: docs.body over 1 MiB
// (change 1), seven values of 1,000,000 '<' (change 2), and 5 MB images
// before and after, past 8 MiB together (change 3).
// largeHarness is the agent harness with largeValuesStatementTimeout. The
// tools here read megabytes of values (a preview runs the revert on trial),
// which can take longer than the default statement timeout on a loaded
// machine. The time limit is not what these tests check.
func largeHarness(t *testing.T, d *guardtest.DB, a *guardtest.Agent) agentEnv {
	t.Helper()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	limits := sqlguard.DefaultLimits()
	limits.StatementTimeout = largeValuesStatementTimeout
	return agentHarnessLimits(t, d, a, keys, limits)
}

type largeEnv struct {
	agentEnv
	run     uuid.UUID
	changes []string
}

func newLargeEnv(t *testing.T) largeEnv {
	t.Helper()
	d := guardtest.New(t)
	cols := make([]string, 0, 7)
	sets := make([]string, 0, 7)
	for i := range 7 {
		cols = append(cols, fmt.Sprintf("c%d text", i))
		sets = append(sets, fmt.Sprintf("c%d = repeat('<', 1000000)", i))
	}
	d.Exec(t, `CREATE TABLE public.docs (id int PRIMARY KEY, body text);
		INSERT INTO public.docs VALUES (1, 'small'), (2, 'two');
		CREATE TABLE public.angles (id int PRIMARY KEY, `+strings.Join(cols, ", ")+`);
		INSERT INTO public.angles (id) VALUES (1);
		CREATE TABLE public.wide (id int PRIMARY KEY, a text, b text, c text, d text, e text);
		INSERT INTO public.wide SELECT 1, repeat('a', 1000000), repeat('b', 1000000), repeat('c', 1000000),
			repeat('d', 1000000), repeat('e', 1000000)`)
	tables := []string{"public.docs", "public.angles", "public.wide"}
	e := largeHarness(t, d, d.NewAgent(t, "bot", tables, tables))
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Large values"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in,
		fmt.Sprintf(`UPDATE public.docs SET body = repeat('x', %d) WHERE id = 1`, bigValue),
		`UPDATE public.angles SET `+strings.Join(sets, ", ")+` WHERE id = 1`,
		`UPDATE public.wide SET a = upper(a), b = upper(b), c = upper(c), d = upper(d), e = upper(e) WHERE id = 1`))
	var ids []string
	rows, err := e.d.Admin.Query(ctx, `SELECT change_id::text FROM basalt_meta.changes WHERE run_id = $1 AND op = 'UPDATE' ORDER BY change_id`, in.RunID)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Len(t, ids, 3)
	return largeEnv{agentEnv: e, run: in.RunID, changes: ids}
}

// callFits calls tool and checks the answer fits the result budget.
func callFits(t *testing.T, h harness, tool string, args map[string]any) map[string]any {
	t.Helper()
	body, isError := h.call(t, tool, args)
	require.False(t, isError, "%s: %v", tool, body)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.Less(t, len(raw), resultsize.MaxBytes, "%s: the answer fits the budget", tool)
	return body
}

func firstRow(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	rows, ok := rec["rowChanges"].([]any)
	require.True(t, ok, "%v", rec)
	require.NotEmpty(t, rows)
	row, ok := rows[0].(map[string]any)
	require.True(t, ok)
	return row
}

// entries reads a largeValues array as the agent gets it.
func entries(t *testing.T, v any) []map[string]any {
	t.Helper()
	list, ok := v.([]any)
	require.True(t, ok, "largeValues: %v", v)
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		require.True(t, ok)
		out = append(out, m)
	}
	return out
}

// TestRunHistoryMarksLargeValues: at limit 1, each record fits the budget:
// a value over 1 MiB is absent with its size and hash, values of many
// escapable bytes are left out by what they cost, and an image past the
// item's 8 MiB is left out whole.
func TestRunHistoryMarksLargeValues(t *testing.T) {
	t.Parallel()
	e := newLargeEnv(t)
	args := map[string]any{"runId": e.run.String(), "limit": 1, "sort": "id"}
	var records []map[string]any
	for {
		page := callFits(t, e.h, "run_history", args)
		records = append(records, items(t, page)...)
		next, ok := page["nextCursor"].(string)
		if !ok {
			break
		}
		args["cursor"] = next
	}
	require.Len(t, records, 3)

	body := firstRow(t, records[0])
	require.Equal(t, map[string]any{"id": json.Number("1")}, body["after"], "body is absent, never null")
	require.Equal(t, map[string]any{"id": json.Number("1"), "body": "small"}, body["before"])
	require.Equal(t, []map[string]any{{
		"in": "AFTER", "column": "body", "bytes": json.Number(fmt.Sprint(bigValue)), "sha256": sum256(strings.Repeat("x", bigValue)),
	}}, entries(t, body["largeValues"]))
	require.NotContains(t, records[0], "largeValues", "the statement and params are small")

	angles := firstRow(t, records[1])
	require.Equal(t, map[string]any{"id": json.Number("1")}, angles["after"])
	marks := entries(t, angles["largeValues"])
	require.Len(t, marks, 7, "1,000,000 '<' are under 1 MiB of text but cost about 7 MB each")
	for i, m := range marks {
		require.Equal(t, fmt.Sprintf("c%d", i), m["column"])
		require.Equal(t, json.Number("1000000"), m["bytes"])
		require.Equal(t, sum256(strings.Repeat("<", 1000000)), m["sha256"])
	}

	wide := firstRow(t, records[2])
	require.NotContains(t, wide, "after", "the image past 8 MiB is left out whole")
	before, ok := wide["before"].(map[string]any)
	require.True(t, ok)
	require.Len(t, before, 6)
	whole := entries(t, wide["largeValues"])
	require.Len(t, whole, 1)
	require.Equal(t, "AFTER", whole[0]["in"])
	require.NotContains(t, whole[0], "column")

	all := callFits(t, e.h, "run_history", map[string]any{"runId": e.run.String()})
	require.Len(t, items(t, all), 3, "the whole run fits one page as well")
}

// TestRunHistorySizeLimitEndsWithASmallerLimit: records that fit alone
// but not together are SIZE_LIMIT, with a smaller limit as the step; at
// limit 1 each one reads.
func TestRunHistorySizeLimitEndsWithASmallerLimit(t *testing.T) {
	t.Parallel()
	e := newLargeEnv(t)
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Wide"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	for i := range 4 {
		f := "upper"
		if i%2 == 1 {
			f = "lower"
		}
		require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, fmt.Sprintf(
			`UPDATE public.wide SET a = %[1]s(a), b = %[1]s(b), c = %[1]s(c), d = %[1]s(d), e = %[1]s(e) WHERE id = 1`, f)))
	}
	body, isError := e.h.call(t, "run_history", map[string]any{"runId": in.RunID.String()})
	requireToolError(t, body, isError, "QUERY_TIMEOUT", "SIZE_LIMIT", "")
	steps, ok := body["nextSteps"].([]any)
	require.True(t, ok)
	step, ok := steps[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "REVISE_CALL", step["action"])
	require.Contains(t, step["text"], "smaller limit")

	args := map[string]any{"runId": in.RunID.String(), "limit": 1}
	n := 0
	for {
		page := callFits(t, e.h, "run_history", args)
		n += len(items(t, page))
		next, ok := page["nextCursor"].(string)
		if !ok {
			break
		}
		args["cursor"] = next
	}
	require.Equal(t, 4, n)
}

// TestPreviewRevertMarksLargeValues: preview_revert pages a run with large
// values at limit 1; each line fits, with its large values named.
func TestPreviewRevertMarksLargeValues(t *testing.T) {
	t.Parallel()
	e := newLargeEnv(t)
	args := map[string]any{"runId": e.run.String(), "limit": 1}
	var lines []map[string]any
	for {
		page := callFits(t, e.h, "preview_revert", args)
		require.EqualValues(t, "3", fmt.Sprint(page["rows"]), "the totals cover the whole preview")
		lines = append(lines, items(t, page)...)
		next, ok := page["nextCursor"].(string)
		if !ok {
			break
		}
		args["cursor"] = next
	}
	require.Len(t, lines, 3)
	byTable := map[string]map[string]any{}
	for _, l := range lines {
		byTable[str(t, l["table"])] = l
	}
	docs := byTable["public.docs"]
	require.Equal(t, map[string]any{"id": json.Number("1")}, docs["now"], "now's body is absent")
	require.Equal(t, []map[string]any{{
		"in": "NOW", "column": "body", "bytes": json.Number(fmt.Sprint(bigValue)), "sha256": sum256(strings.Repeat("x", bigValue)),
	}}, entries(t, docs["largeValues"]))
	wide := byTable["public.wide"]
	require.Contains(t, wide, "now")
	require.NotContains(t, wide, "set", "set takes the line past 8 MiB: left out whole")
	whole := entries(t, wide["largeValues"])
	require.Len(t, whole, 1)
	require.Equal(t, "SET", whole[0]["in"])
}

// TestPreviewRevertCutsChangeIDs: a line of a row many changes touched
// names the first 100 and counts the rest.
func TestPreviewRevertCutsChangeIDs(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.counter (id int PRIMARY KEY, n int); INSERT INTO public.counter VALUES (1, 0)`)
	tables := []string{"public.counter"}
	e := largeHarness(t, d, d.NewAgent(t, "bot", tables, tables))
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Count"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	stmts := make([]string, 0, 120)
	for range 120 {
		stmts = append(stmts, `UPDATE public.counter SET n = n + 1 WHERE id = 1`)
	}
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, stmts...))
	page := callFits(t, e.h, "preview_revert", map[string]any{"runId": in.RunID.String()})
	line := items(t, page)[0]
	require.Len(t, line["changeIds"], 100)
	require.Equal(t, json.Number("20"), line["moreChangeIds"])
}

// TestRevertPlanPagesPastALargeLineAndRestoresIt: a signed plan's line
// whose restored value is over 1 MiB reads with a marker at limit 1, and
// apply_revert_batch restores the full value: Postgres applies it from
// the stored rows, not from what the agent read.
func TestRevertPlanPagesPastALargeLineAndRestoresIt(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, CASE WHEN g = 1 THEN repeat('x', %d) ELSE 'before' END
		FROM generate_series(1, %d) g`, bigValue, planRows))
	tables := []string{"public.items"}
	e := largeHarness(t, d, d.NewAgent(t, "bot", tables, tables))
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Bulk update"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	stmts := make([]string, 0, planRows/10)
	for i := 0; i < planRows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'agent' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, stmts...))
	prep, err := guard.PrepareRevert(ctx, e.a.Conn, guardmodel.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo the bulk update")
	require.NoError(t, err)
	require.True(t, prep.Batched)
	as, err := e.person.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.a.Conn, prep.RevertID, as)
	require.NoError(t, err)
	id := prep.RevertID.String()

	big := strings.Repeat("x", bigValue)
	args := map[string]any{"revertId": id, "limit": 1}
	found := false
	for !found {
		page := callFits(t, e.h, "revert_plan", args)
		plan, ok := items(t, page)[0]["plan"].(map[string]any)
		require.True(t, ok)
		if marks, ok := plan["largeValues"]; ok {
			set, ok := plan["set"].(map[string]any)
			require.True(t, ok, "the rest of set is kept: %v", plan)
			require.NotContains(t, set, "v", "v is absent from set, never null")
			require.Equal(t, []map[string]any{{"in": "SET", "column": "v", "bytes": json.Number(fmt.Sprint(bigValue)), "sha256": sum256(big)}},
				entries(t, marks))
			found = true
			continue
		}
		args["cursor"] = str(t, page["nextCursor"])
	}

	applyEveryBatch(t, e.h, id)
	var restored bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT v = repeat('x', $1) FROM public.items WHERE id = 1`, bigValue).Scan(&restored))
	require.True(t, restored, "Postgres restores the full value")
	require.Equal(t, planRows, itemsLeft(t, d, "before")+1)
}

// TestWriteReturningOneRowTooLarge: a write whose RETURNING row costs more
// than the budget alone is ROW_TOO_LARGE, and nothing is written.
func TestWriteReturningOneRowTooLarge(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.docs (id int PRIMARY KEY, body text); INSERT INTO public.docs VALUES (2, 'two')`)
	tables := []string{"public.docs"}
	e := largeHarness(t, d, d.NewAgent(t, "bot", tables, tables))
	body, isError := e.h.call(t, "write", map[string]any{
		"sql": "UPDATE public.docs SET body = repeat('<', 2700000) WHERE id = 2 RETURNING id, body", "intent": "Fill doc 2",
	})
	requireToolError(t, body, isError, "QUERY_TIMEOUT", "ROW_TOO_LARGE", "")
	require.Contains(t, body["message"], "its largest columns: body (18.0 MiB)")
	var v string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT body FROM public.docs WHERE id = 2`).Scan(&v))
	require.Equal(t, "two", v, "the write was rolled back")
}

// TestALimitOfOneReadsOneItemOnly: two lines in a row whose images are each
// just under 8 MiB page at limit 1. The line past the limit only tells that
// another page follows: its values are never read, so the page fits.
func TestALimitOfOneReadsOneItemOnly(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	cols := make([]string, 0, 8)
	sets := make([]string, 0, 8)
	for i := range 8 {
		cols = append(cols, fmt.Sprintf("c%d text", i))
		sets = append(sets, fmt.Sprintf("c%d = repeat('x', 1040000)", i))
	}
	d.Exec(t, `CREATE TABLE public.big (id int PRIMARY KEY, `+strings.Join(cols, ", ")+`);
		INSERT INTO public.big (id) VALUES (1), (2)`)
	tables := []string{"public.big"}
	e := largeHarness(t, d, d.NewAgent(t, "bot", tables, tables))
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Fill"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, `UPDATE public.big SET `+strings.Join(sets, ", ")))

	args := map[string]any{"runId": in.RunID.String(), "limit": 1}
	n := 0
	for {
		page := callFits(t, e.h, "preview_revert", args)
		n += len(items(t, page))
		next, ok := page["nextCursor"].(string)
		if !ok {
			break
		}
		args["cursor"] = next
	}
	require.Equal(t, 2, n)
}
