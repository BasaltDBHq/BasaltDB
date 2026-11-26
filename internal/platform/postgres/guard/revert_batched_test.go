package guard_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// bulkRows is a run larger than one call takes (revert.MaxLines).
const bulkRows = 1210

// bulkEnv: a public.items table of bulkRows rows ('before'), and an agent
// run that set every one to 'agent', ten rows per statement (allowed
// without approval).
type bulkEnv struct {
	d  *guardtest.DB
	a  *guardtest.Agent
	p  *passkeytest.Authenticator
	in guard.Intent
}

func newBulkEnv(t *testing.T) bulkEnv {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, 'before' FROM generate_series(1, %d) g`, bulkRows))
	items := []string{"public.items"}
	a := d.NewAgent(t, "bot", items, items)
	e := bulkEnv{d: d, a: a, p: person(t, d), in: newRun(t, a, "Bulk update items")}
	stmts := make([]string, 0, bulkRows/10)
	for i := 0; i < bulkRows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'agent' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, e.in, stmts...))
	return e
}

func (e bulkEnv) scope() revertstore.Scope {
	return revertstore.Scope{Kind: revert.ScopeRun, ID: e.in.RunID}
}

// prepareAndSign prepares the run's revert and signs it with the person's
// passkey through apply_revert.
func (e bulkEnv) prepareAndSign(t *testing.T) (revertstore.PreparedRevert, revertstore.AppliedRevert) {
	t.Helper()
	prep, as := prepareSigned(t, e.a, e.p, revert.ScopeRun, e.in.RunID)
	signed, err := guard.ApplyRevert(context.Background(), e.a.Conn, prep.RevertID, as)
	require.NoError(t, err)
	return prep, signed
}

// pendingLines is the next page of pending line numbers, as an agent reads
// them through revert_plan.
func pendingLines(t *testing.T, c *pgx.Conn, revertID uuid.UUID, limit int) []int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT line_no FROM basalt_meta.agent_revert_lines
		WHERE revert_id = $1 AND outcome = 'PENDING' ORDER BY line_no LIMIT $2`, revertID, limit)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[int])
	require.NoError(t, err)
	return out
}

// applyAll runs the agent's loop until no line is pending.
func (e bulkEnv) applyAll(t *testing.T, revertID uuid.UUID) []revertstore.BatchResult {
	t.Helper()
	var out []revertstore.BatchResult
	for {
		lines := pendingLines(t, e.a.Conn, revertID, revert.MaxBatch)
		if len(lines) == 0 {
			return out
		}
		res, err := guard.ApplyRevertBatch(context.Background(), e.a.Conn, revertID, lines)
		require.NoError(t, err)
		out = append(out, res)
	}
}

func TestPrepareBatchedPlan(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	e.d.Exec(t, `UPDATE public.items SET v = 'person' WHERE id IN (5, 6)`)
	ctx := context.Background()

	prep, err := guard.PrepareRevert(ctx, e.a.Conn, e.scope(), "Undo the bulk update")
	require.NoError(t, err)
	require.True(t, prep.Batched)
	b, err := revert.Request{RevertID: prep.RevertID, Binding: prep.BindingText, Lines: prep.Lines}.Check()
	require.NoError(t, err, "the Go codec accepts the sample Postgres built")
	require.True(t, b.Batched)
	require.Equal(t, bulkRows-2, b.Rows)
	require.Equal(t, 2, b.Skipped)
	require.Len(t, prep.Lines, revert.MaxLines)

	// rowsHash covers every line of the plan, in signed order, and the
	// sample is the one the Go codec builds from them.
	rows, err := e.a.Conn.Query(ctx, `SELECT line FROM basalt_meta.agent_revert_lines
		WHERE revert_id = $1 ORDER BY line COLLATE "C"`, prep.RevertID)
	require.NoError(t, err)
	all, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Len(t, all, bulkRows)
	require.Equal(t, b.RowsHash, approval.RowsHash(all))
	sample, err := reverttest.Sample(all)
	require.NoError(t, err)
	require.Equal(t, sample, prep.Lines)

	// Numbered 1..N in execution order: the SKIP lines last.
	nos := pendingLines(t, e.a.Conn, prep.RevertID, bulkRows)
	require.Len(t, nos, bulkRows)
	require.Equal(t, 1, nos[0])
	require.Equal(t, bulkRows, nos[len(nos)-1])
	require.Equal(t, 2, count(t, e.a.Conn, `SELECT count(line_no)::int FROM basalt_meta.agent_revert_lines
		WHERE revert_id = $1 AND line_no > $2 AND line::jsonb ->> 'action' = 'SKIP'`, prep.RevertID, bulkRows-2))

	var status string
	var batched bool
	var pending int
	require.NoError(t, e.a.Conn.QueryRow(ctx, `SELECT status, batched, pending FROM basalt_meta.agent_reverts
		WHERE revert_id = $1`, prep.RevertID).Scan(&status, &batched, &pending))
	require.Equal(t, "PENDING", status)
	require.True(t, batched)
	require.Equal(t, bulkRows, pending)

	// Preview has no cap either.
	require.Len(t, previewRevert(t, e.a.Conn, revert.ScopeRun, e.in.RunID), bulkRows)
}

// TestBatchedSampleKeepsRestores: with more SKIP lines than half a sample,
// Postgres still puts RESTORE lines in the link, split as revert.Sample does
// (decision RSS-1). Before version 17 this plan's sample held 700 SKIP lines
// and only 300 RESTORE lines; with 1000 SKIP lines it held none.
func TestBatchedSampleKeepsRestores(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	const skips = 700
	e.d.Exec(t, fmt.Sprintf(`UPDATE public.items SET v = 'person' WHERE id <= %d`, skips))
	ctx := context.Background()
	prep, err := guard.PrepareRevert(ctx, e.a.Conn, e.scope(), "Undo the bulk update")
	require.NoError(t, err)
	b, err := revert.Request{RevertID: prep.RevertID, Binding: prep.BindingText, Lines: prep.Lines}.Check()
	require.NoError(t, err, "the Go codec accepts the sample Postgres built")
	require.Equal(t, skips, b.Skipped)
	require.Equal(t, bulkRows-skips, b.Rows)

	rows, err := e.a.Conn.Query(ctx, `SELECT line FROM basalt_meta.agent_revert_lines
		WHERE revert_id = $1 ORDER BY line COLLATE "C"`, prep.RevertID)
	require.NoError(t, err)
	all, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	sample, err := reverttest.Sample(all)
	require.NoError(t, err)
	require.Equal(t, sample, prep.Lines)

	restores := 0
	for _, text := range prep.Lines {
		l, err := revert.ParseLine(text)
		require.NoError(t, err)
		if l.Action == revert.ActionRestore {
			restores++
		}
	}
	require.Equal(t, revert.SampleShare, restores)
}

func TestBatchedRevertAppliesInBatches(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	e.d.Exec(t, `UPDATE public.items SET v = 'person' WHERE id = 5`)

	prep, signed := e.prepareAndSign(t)
	require.True(t, signed.Batched)
	require.Zero(t, signed.Rows, "the signature writes no row")
	require.Equal(t, 1, signed.Skipped)
	require.Equal(t, bulkRows-1, signed.Pending)
	require.NotNil(t, signed.ApplyBy)
	require.WithinDuration(t, time.Now().Add(revert.ApplyWindow), *signed.ApplyBy, time.Minute)
	require.Equal(t, bulkRows-1, count(t, e.d.Admin, `SELECT count(id)::int FROM public.items WHERE v = 'agent'`))
	require.Equal(t, "APPLYING", scalarOf[string](t, e.a.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))

	batches := e.applyAll(t, prep.RevertID)
	require.Len(t, batches, (bulkRows-1+revert.MaxBatch-1)/revert.MaxBatch)
	for i, res := range batches {
		require.Equal(t, i+1, res.Batch)
		require.Equal(t, prep.RevertID, res.RevertID)
	}
	last := batches[len(batches)-1]
	require.Equal(t, "APPLIED", last.Status)
	require.Equal(t, bulkRows-1, last.Restored)
	require.Equal(t, 1, last.Skipped)
	require.Zero(t, last.Pending)
	require.Equal(t, "APPLYING", batches[0].Status)
	require.Len(t, batches[0].Items, revert.MaxBatch)
	require.Equal(t, guardmodel.OutcomeRestored, batches[0].Items[0].Outcome)

	require.Equal(t, bulkRows-1, count(t, e.d.Admin, `SELECT count(id)::int FROM public.items WHERE v = 'before'`))
	require.Equal(t, "person", scalarOf[string](t, e.d.Admin, `SELECT v FROM public.items WHERE id = 5`))
	require.Equal(t, "APPLIED", scalarOf[string](t, e.a.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))

	// Progress in the ledger and the chain.
	revertChange := scalarOf[uuid.UUID](t, e.a.Conn, `SELECT change_id FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID)
	require.Equal(t, bulkRows-1, scalarOf[int](t, e.d.Admin, `SELECT rows FROM basalt_meta.changes WHERE change_id = $1`, revertChange))
	var kinds []string
	require.NoError(t, e.d.Admin.QueryRow(ctx, `SELECT array_agg(kind ORDER BY seq) FROM basalt_meta.ledger
		WHERE kind IN ('REVERT_PENDING', 'REVERT_SIGNED', 'REVERT_BATCH', 'REVERTED')`).Scan(&kinds))
	want := make([]string, 0, len(batches)+3)
	want = append(want, "REVERT_PENDING", "REVERT_SIGNED")
	for range batches {
		want = append(want, "REVERT_BATCH")
	}
	require.Equal(t, append(want, "REVERTED"), kinds)
	require.Equal(t, bulkRows-1, count(t, e.d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'ROW_CHANGE' AND change_id = $1`, revertChange))
	require.Nil(t, guardVerify(t, e.d))

	// REVERTED only where every row was restored: the change that wrote
	// item 5 stays APPLIED and names the revert.
	require.Equal(t, 1, count(t, e.d.Admin, `SELECT count(change_id)::int FROM basalt_meta.changes
		WHERE run_id = $1 AND status = 'APPLIED' AND $2 = ANY (reverted_by)`, e.in.RunID, revertChange))
	require.Equal(t, bulkRows/10-1, count(t, e.d.Admin, `SELECT count(change_id)::int FROM basalt_meta.changes
		WHERE run_id = $1 AND status = 'REVERTED' AND reverted_by = ARRAY[$2::uuid]`, e.in.RunID, revertChange))
}

func TestBatchChecks(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	prep, as := prepareSigned(t, e.a, e.p, revert.ScopeRun, e.in.RunID)

	_, err := guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{1})
	requireRevertInvalid(t, err, "not signed")

	_, err = guard.ApplyRevert(ctx, e.a.Conn, prep.RevertID, as)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.a.Conn, prep.RevertID, as)
	requireRevertRefused(t, err, guard.RevertAlreadySigned, "already signed")

	other := e.d.NewAgent(t, "other", []string{"public.items"}, []string{"public.items"})
	tooMany := make([]int, revert.MaxBatch+1)
	for i := range tooMany {
		tooMany[i] = i + 1
	}
	cases := []struct {
		name   string
		c      *pgx.Conn
		id     uuid.UUID
		lines  []int
		detail string
	}{
		{"another agent", other.Conn, prep.RevertID, []int{1}, guard.RevertNotFound},
		{"an unknown revert", e.a.Conn, uuid.Must(uuid.NewV7()), []int{1}, guard.RevertNotFound},
		{"no lines", e.a.Conn, prep.RevertID, []int{}, "1 to 200 lines"},
		{"over the batch size", e.a.Conn, prep.RevertID, tooMany, "1 to 200 lines"},
		{"a line twice", e.a.Conn, prep.RevertID, []int{1, 2, 1}, "line 1 twice"},
		{"a line not in the plan", e.a.Conn, prep.RevertID, []int{1, bulkRows + 1}, fmt.Sprintf("line %d is not in the plan", bulkRows+1)},
		{"line zero", e.a.Conn, prep.RevertID, []int{0}, "line 0 is not in the plan"},
	}
	for _, tc := range cases {
		_, err := guard.ApplyRevertBatch(ctx, tc.c, tc.id, tc.lines)
		requireRevertInvalid(t, err, tc.detail)
	}
	require.Zero(t, count(t, e.d.Admin, `SELECT count(id)::int FROM public.items WHERE v = 'before'`), "nothing was written")

	_, err = guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{1, 2})
	require.NoError(t, err)
	_, err = guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{2, 3})
	requireRevertInvalid(t, err, "line 2 was already applied in batch 1")

	e.d.Exec(t, `UPDATE basalt_meta.reverts SET apply_by = now() - interval '1 second' WHERE revert_id = $1`, prep.RevertID)
	_, err = guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{3})
	requireCode(t, err, guard.CodeRevertExpired)
	require.Equal(t, "EXPIRED", scalarOf[string](t, e.a.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))

	// A one-call revert has no batches.
	in := newRun(t, e.a, "One row")
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, `UPDATE public.items SET v = 'x' WHERE id = 1`))
	small, smallAs := prepareSigned(t, e.a, e.p, revert.ScopeRun, in.RunID)
	require.False(t, small.Batched)
	_, err = guard.ApplyRevertBatch(ctx, e.a.Conn, small.RevertID, []int{1})
	requireRevertInvalid(t, err, "applied in one call")
	_, err = guard.ApplyRevert(ctx, e.a.Conn, small.RevertID, smallAs)
	require.NoError(t, err)
}

// TestBatchPeopleWinPerLine: a row a person changes after the signature is
// skipped when its batch runs; the rest of the batch is restored.
func TestBatchPeopleWinPerLine(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	prep, _ := e.prepareAndSign(t)
	lineOf := func(id int) int {
		return scalarOf[int](t, e.a.Conn, `SELECT line_no FROM basalt_meta.agent_revert_lines
			WHERE revert_id = $1 AND line::jsonb -> 'key' ->> 'id' = $2`, prep.RevertID, fmt.Sprint(id))
	}
	e.d.Exec(t, `UPDATE public.items SET v = 'person' WHERE id = 7`)
	res, err := guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{lineOf(7), lineOf(8)})
	require.NoError(t, err)
	require.Equal(t, []revertstore.BatchItem{
		{Line: lineOf(7), Outcome: guardmodel.OutcomeSkipped, Conflict: revert.ConflictChangedAfter},
		{Line: lineOf(8), Outcome: guardmodel.OutcomeRestored},
	}, res.Items)
	require.Equal(t, "person", scalarOf[string](t, e.d.Admin, `SELECT v FROM public.items WHERE id = 7`))
	require.Equal(t, "before", scalarOf[string](t, e.d.Admin, `SELECT v FROM public.items WHERE id = 8`))

	e.applyAll(t, prep.RevertID)
	require.Equal(t, 1, count(t, e.d.Admin, `SELECT count(change_id)::int FROM basalt_meta.changes
		WHERE run_id = $1 AND status = 'APPLIED' AND reverted_by IS NOT NULL`, e.in.RunID))
}

// TestBatchedRevertResumes: a batch whose transaction never commits (the
// agent crashed) leaves nothing behind; the same lines apply afterwards.
func TestBatchedRevertResumes(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	prep, _ := e.prepareAndSign(t)
	head := scalarOf[int64](t, e.d.Admin, `SELECT seq FROM basalt_meta.chain_head`)

	tx, err := e.a.Conn.Begin(ctx)
	require.NoError(t, err)
	_, err = guard.ApplyRevertBatch(ctx, tx, prep.RevertID, []int{1, 2, 3})
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	require.Equal(t, head, scalarOf[int64](t, e.d.Admin, `SELECT seq FROM basalt_meta.chain_head`))
	require.Len(t, pendingLines(t, e.a.Conn, prep.RevertID, bulkRows), bulkRows)

	res, err := guard.ApplyRevertBatch(ctx, e.a.Conn, prep.RevertID, []int{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, 1, res.Batch)
	require.Equal(t, 3, res.Restored)
	e.applyAll(t, prep.RevertID)
	require.Equal(t, bulkRows, count(t, e.d.Admin, `SELECT count(id)::int FROM public.items WHERE v = 'before'`))
	require.Nil(t, guardVerify(t, e.d))
}

// TestBatchedParentsBeforeChildren: the agent deleted each folder's files,
// then the folder, so the ledger has every file before its folder. The
// plan numbers lines in the order the trial's writes landed, so applying
// them in number order, across batches, re-inserts each folder before its
// files.
func TestBatchedParentsBeforeChildren(t *testing.T) {
	t.Parallel()
	const (
		parents  = 21
		children = 48 // one action deletes at most 50 rows
	)
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.folders (id int PRIMARY KEY, name text NOT NULL);
		CREATE TABLE public.files (id int PRIMARY KEY, folder_id int NOT NULL REFERENCES public.folders, name text NOT NULL);
		INSERT INTO public.folders SELECT g, 'folder ' || g FROM generate_series(1, %d) g;
		INSERT INTO public.files SELECT g, (g - 1) / %d + 1, 'file ' || g FROM generate_series(1, %d) g`,
		parents, children, parents*children))
	tables := []string{"public.folders", "public.files"}
	a := d.NewAgent(t, "bot", tables, tables)
	p := person(t, d)
	in := newRun(t, a, "Clear old folders")
	for i := 1; i <= parents; i++ {
		approvedWrite(t, a, p, in, `DELETE FROM public.files WHERE folder_id = $1`, []any{i}, []string{})
		approvedWrite(t, a, p, in, `DELETE FROM public.folders WHERE id = $1`, []any{i}, []string{})
	}
	require.Zero(t, count(t, d.Admin, `SELECT count(id)::int FROM public.files`))

	e := bulkEnv{d: d, a: a, p: p, in: in}
	prep, signed := e.prepareAndSign(t)
	require.Equal(t, parents*(children+1), signed.Pending)
	for _, res := range e.applyAll(t, prep.RevertID) {
		for _, it := range res.Items {
			require.Equal(t, guardmodel.OutcomeRestored, it.Outcome, "line %d: %s %s", it.Line, it.Conflict, it.StoreCode)
		}
	}
	require.Equal(t, parents, count(t, d.Admin, `SELECT count(id)::int FROM public.folders`))
	require.Equal(t, parents*children, count(t, d.Admin, `SELECT count(id)::int FROM public.files`))

	// Every file's line comes after its folder's line.
	require.Equal(t, parents*children, count(t, a.Conn, `SELECT count(f.line_no)::int
		FROM basalt_meta.agent_revert_lines f JOIN basalt_meta.agent_revert_lines p
		  ON p.revert_id = f.revert_id AND p.line::jsonb ->> 'resource' = 'public.folders'
		 AND p.line::jsonb -> 'key' ->> 'id' = f.line::jsonb -> 'set' ->> 'folder_id'
		WHERE f.revert_id = $1 AND f.line::jsonb ->> 'resource' = 'public.files' AND p.line_no < f.line_no`, prep.RevertID))
}
