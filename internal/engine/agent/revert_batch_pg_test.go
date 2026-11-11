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
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// planRows is one more row than a one-call revert takes.
const planRows = revert.MaxLines + 10

// batchEnv: an agent that set every row of public.items in one run, and a
// large revert of that run prepared by the person's CLI on the agent's
// credential (as basalt revert does).
type batchEnv struct {
	agentEnv
	runID uuid.UUID
	prep  guard.PreparedRevert
}

func itemsLeft(t *testing.T, d *guardtest.DB, v string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(id)::int FROM public.items WHERE v = $1`, v).Scan(&n))
	return n
}

// newBatchEnv builds a batchEnv; pagesOrigin, when given, is the origin of
// the engine's local pages, as for agentHarnessFor.
func newBatchEnv(t *testing.T, pagesOrigin ...string) batchEnv {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, 'before' FROM generate_series(1, %d) g`, planRows))
	tables := []string{"public.items"}
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables), pagesOrigin...)
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Bulk update"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	stmts := make([]string, 0, planRows/10)
	for i := 0; i < planRows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'agent' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, stmts...))
	prep, err := guard.PrepareRevert(ctx, e.a.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo the bulk update")
	require.NoError(t, err)
	require.True(t, prep.Batched)
	return batchEnv{agentEnv: e, runID: in.RunID, prep: prep}
}

// sign is the person signing the plan on the revert page and basalt revert
// relaying the code.
func (e batchEnv) sign(t *testing.T) {
	t.Helper()
	as, err := e.person.Sign(revert.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(context.Background(), e.a.Conn, e.prep.RevertID, as)
	require.NoError(t, err)
}

func lineNumbers(t *testing.T, list []map[string]any) []int {
	t.Helper()
	out := make([]int, 0, len(list))
	for _, l := range list {
		n, err := l["line"].(json.Number).Int64()
		require.NoError(t, err)
		out = append(out, int(n))
	}
	return out
}

// applyEveryBatch is the agent's loop over a signed plan: list pending
// lines, apply them, until none is left. It returns the batches applied.
func applyEveryBatch(t *testing.T, h harness, id string) int {
	t.Helper()
	batches := 0
	for {
		page, isError := h.call(t, "revert_plan", map[string]any{"revertId": id, "pending": true, "limit": 200})
		require.False(t, isError, "%v", page)
		lines := lineNumbers(t, items(t, page))
		if len(lines) == 0 {
			require.Equal(t, "APPLIED", page["status"])
			require.NotContains(t, page, "nextCursor")
			return batches
		}
		res, isError := h.call(t, "apply_revert_batch", map[string]any{"revertId": id, "lines": lines})
		require.False(t, isError, "%v", res)
		batches++
		require.EqualValues(t, fmt.Sprint(batches), res["batch"])
		require.Len(t, items(t, res), len(lines))
	}
}

func TestRevertPlanAndBatchTools(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	id := e.prep.RevertID.String()

	before, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": id})
	require.False(t, isError, "%v", before)
	require.Equal(t, "PENDING", before["status"])
	require.Equal(t, "RUN", before["scope"])
	require.Equal(t, e.runID.String(), before["scopeId"])
	require.EqualValues(t, fmt.Sprint(planRows), before["lines"])
	require.EqualValues(t, fmt.Sprint(planRows), before["pending"])
	require.EqualValues(t, "200", before["maxBatch"])
	require.NotContains(t, before, "applyBy")
	require.Len(t, items(t, before), 50, "default page")
	first := items(t, before)[0]
	require.EqualValues(t, "1", first["line"])
	require.Equal(t, "PENDING", first["outcome"])
	plan, ok := first["plan"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "RESTORE", plan["action"])
	require.Equal(t, "public.items", plan["table"])
	// Not signed yet: the link to sign it, for the agent to hand over.
	link := str(t, before["revertUrl"])
	require.True(t, strings.HasPrefix(link, links.DefaultLocal+"/reverts/"+id+"#2."), "no local pages: the long link: %s", link)
	require.Contains(t, before["personMessage"], "Revert of run "+e.runID.String()+" ready for your review: ")
	require.Contains(t, before["personMessage"], "Why: Undo the bulk update. Review and sign with your passkey: "+link)
	require.Contains(t, before["personMessage"], fmt.Sprintf("It covers %d rows: you sign it once, and the agent then restores it in batches within 24 hours", planRows))

	body, isError := e.h.call(t, "apply_revert_batch", map[string]any{"revertId": id, "lines": []int{1}})
	requireToolError(t, body, isError, "REVERT_INVALID", "", "")
	require.Contains(t, body["message"], "not signed")

	e.sign(t)
	page, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": id, "pending": true, "limit": 500})
	require.False(t, isError, "%v", page)
	require.Equal(t, "APPLYING", page["status"])
	require.Contains(t, page, "applyBy")
	require.Len(t, items(t, page), 200, "limit clamps to 200")
	require.Contains(t, page, "nextCursor")
	next, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": id, "pending": true, "limit": 200, "cursor": str(t, page["nextCursor"])})
	require.False(t, isError, "%v", next)
	require.Equal(t, 201, lineNumbers(t, items(t, next))[0])

	batches := applyEveryBatch(t, e.h, id)
	require.Equal(t, (planRows+revert.MaxBatch-1)/revert.MaxBatch, batches)
	require.Equal(t, planRows, itemsLeft(t, e.d, "before"))

	done, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": id, "limit": 1})
	require.False(t, isError, "%v", done)
	require.EqualValues(t, fmt.Sprint(planRows), done["restored"])
	require.EqualValues(t, "0", done["pending"])
	require.Equal(t, "RESTORED", items(t, done)[0]["outcome"])
	require.EqualValues(t, "1", items(t, done)[0]["batch"])

	hist, isError := e.h.call(t, "run_history", map[string]any{"runId": e.runID.String(), "limit": 1})
	require.False(t, isError, "%v", hist)
	require.Equal(t, "REVERTED", items(t, hist)[0]["status"])
}

func TestRevertBatchToolErrors(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	e.sign(t)
	id := e.prep.RevertID.String()
	unknown := uuid.Must(uuid.NewV7()).String()
	tooMany := make([]int, revert.MaxBatch+1)
	for i := range tooMany {
		tooMany[i] = i + 1
	}
	for _, args := range []map[string]any{
		{"revertId": id},
		{"revertId": id, "lines": []int{}},
		{"revertId": id, "lines": tooMany},
		{"revertId": id, "lines": []int{1, 1}},
		{"revertId": id, "lines": []int{0}},
		{"revertId": "not-a-uuid", "lines": []int{1}},
		{"revertId": id, "lines": []int{1}, "force": true},
	} {
		body, isError := e.h.call(t, "apply_revert_batch", args)
		requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	}
	body, isError := e.h.call(t, "apply_revert_batch", map[string]any{"revertId": unknown, "lines": []int{1}})
	requireToolError(t, body, isError, "REVERT_INVALID", "", "")
	body, isError = e.h.call(t, "apply_revert_batch", map[string]any{"revertId": id, "lines": []int{planRows + 1}})
	requireToolError(t, body, isError, "REVERT_INVALID", "", "")

	e.d.Exec(t, `UPDATE basalt_meta.reverts SET apply_by = now() - interval '1 second' WHERE revert_id = $1`, e.prep.RevertID)
	body, isError = e.h.call(t, "apply_revert_batch", map[string]any{"revertId": id, "lines": []int{1}})
	requireToolError(t, body, isError, "REVERT_EXPIRED", "", "")

	for _, args := range []map[string]any{
		{},
		{"revertId": id, "sort": "-line"},
		{"revertId": id, "cursor": "%%%"},
		{"revertId": id, "outcome": "PENDING"},
	} {
		body, isError := e.h.call(t, "revert_plan", args)
		requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	}
	body, isError = e.h.call(t, "revert_plan", map[string]any{"revertId": unknown})
	requireToolError(t, body, isError, "NOT_FOUND", "", "")
}

// A revert of up to 1000 lines is applied in one call and has no plan.
func TestRevertPlanOfOneCallRevert(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Win a lead"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 70`))
	prep, err := guard.PrepareRevert(ctx, e.a.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo")
	require.NoError(t, err)
	body, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": prep.RevertID.String()})
	requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	require.Contains(t, body["message"], "one call")
}
