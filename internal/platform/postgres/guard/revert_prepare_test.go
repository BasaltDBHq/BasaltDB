package guard_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

func tableDigest(t *testing.T, d *guardtest.DB, table string) string {
	t.Helper()
	// Plain SQL: test fixture on a fixed table name.
	return scalarOf[string](t, d.Admin, fmt.Sprintf(`SELECT coalesce(md5(string_agg(x::text, ',' ORDER BY x::text)), '') FROM %s x`, table))
}

func TestPreviewRevertWritesNothing(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Change two leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id IN (80, 81)`))
	before := tableDigest(t, d, "public.leads")
	head := scalarOf[int64](t, d.Admin, `SELECT seq FROM basalt_meta.chain_head`)

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 2)
	require.Equal(t, before, tableDigest(t, d, "public.leads"))
	require.Equal(t, head, scalarOf[int64](t, d.Admin, `SELECT seq FROM basalt_meta.chain_head`))
	require.Zero(t, count(t, d.Admin, `SELECT count(tx)::int FROM basalt_meta.revert_running`))
	require.Nil(t, guardVerify(t, d))
}

func guardVerify(t *testing.T, d *guardtest.DB) *int64 {
	t.Helper()
	return scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`)
}

// The agent inserted a lead; a person then added a note to it. Deleting
// the lead would cascade into the person's note: CASCADE, kept.
func TestPreviewCascadeConflict(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Add leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `INSERT INTO public.leads (id, name) VALUES (950, 'a'), (951, 'b')`))
	d.Exec(t, `INSERT INTO public.lead_notes (id, lead_id, note) VALUES (900, 950, 'a person''s note')`)

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Equal(t, revert.ConflictCascade, conflictOf(lineFor(t, lines, "public.leads", `{"id":950}`)))
	require.Empty(t, conflictOf(lineFor(t, lines, "public.leads", `{"id":951}`)))
}

func TestPreviewConstraintConflict(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.users (id int PRIMARY KEY, email text NOT NULL UNIQUE);
		INSERT INTO public.users VALUES (1, 'a@x'), (2, 'b@x')`)
	users := []string{"public.users"}
	a := d.NewAgent(t, "bot", users, users)
	in := newRun(t, a, "Change an email")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.users SET email = 'c@x' WHERE id = 1`))
	d.Exec(t, `UPDATE public.users SET email = 'a@x' WHERE id = 2`) // a person reuses the old address

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 1)
	require.Equal(t, revert.ConflictConstraint, conflictOf(lines[0]))
	require.Equal(t, "23505", *lines[0].SQLState)
}

// A tree deleted by an FK cascade on itself comes back whole: the retry
// re-inserts parents before children whatever the ledger order.
func TestPreviewRestoresCascadedTree(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.nodes (id int PRIMARY KEY, parent int REFERENCES public.nodes ON DELETE CASCADE, label text);
		INSERT INTO public.nodes VALUES (1, NULL, 'root'), (2, 1, 'a'), (3, 1, 'b'), (4, 2, 'a.1'), (5, 4, 'a.1.x')`)
	nodes := []string{"public.nodes"}
	a := d.NewAgent(t, "bot", nodes, nodes)
	p := person(t, d)
	in := newRun(t, a, "Prune the tree")
	approvedWrite(t, a, p, in, `DELETE FROM public.nodes WHERE id = $1`, []any{1}, []string{})
	require.Zero(t, count(t, d.Admin, `SELECT count(id)::int FROM public.nodes`))

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 5)
	for _, l := range lines {
		require.Equal(t, revert.ActionRestore, l.Action, string(l.Key))
		require.Equal(t, "INSERT", l.Op)
	}
}

// A parent that cannot come back takes its child with it: CONSTRAINT
// 23503 on the child, named rather than half-restored.
func TestPreviewDependentRowSkipped(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.teams (id int PRIMARY KEY, name text NOT NULL UNIQUE);
		CREATE TABLE public.members (id int PRIMARY KEY, team int NOT NULL REFERENCES public.teams, name text);
		INSERT INTO public.teams VALUES (1, 'red'), (2, 'blue');
		INSERT INTO public.members VALUES (10, 1, 'ann'), (20, 2, 'bob')`)
	tables := []string{"public.teams", "public.members"}
	a := d.NewAgent(t, "bot", tables, tables)
	p := person(t, d)
	in := newRun(t, a, "Disband red")
	approvedWrite(t, a, p, in, `DELETE FROM public.members WHERE id = $1`, []any{10}, []string{})
	approvedWrite(t, a, p, in, `DELETE FROM public.teams WHERE id = $1`, []any{1}, []string{})
	d.Exec(t, `INSERT INTO public.teams VALUES (3, 'red')`) // a person reuses the name

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	team := lineFor(t, lines, "public.teams", `{"id":1}`)
	require.Equal(t, revert.ConflictConstraint, conflictOf(team))
	require.Equal(t, "23505", *team.SQLState)
	member := lineFor(t, lines, "public.members", `{"id":10}`)
	require.Equal(t, revert.ConflictConstraint, conflictOf(member))
	require.Equal(t, "23503", *member.SQLState)
}

func TestPrepareRevertStoresBinding(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Bulk update")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id IN (82, 83)`))
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 83`)

	p, err := guard.PrepareRevert(ctx, a.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo the bulk update")
	require.NoError(t, err)
	req := revert.Request{RevertID: p.RevertID, Binding: p.BindingText, Lines: p.Lines}
	b, err := req.Check()
	require.NoError(t, err, "the Go codec accepts what Postgres built")
	require.Equal(t, revert.Select{Scope: revert.ScopeRun, ScopeID: in.RunID, Agents: []string{a.Role}}, b.Select)
	require.Nil(t, b.Proposed, "proposed is omitted while it equals select")
	require.False(t, b.Widened)
	require.Nil(t, b.AgentRows)
	require.Equal(t, a.Role, b.RequestedBy)
	require.Equal(t, "Undo the bulk update", b.Intent)
	require.Equal(t, 1, b.Rows)
	require.Equal(t, 1, b.Skipped)
	require.WithinDuration(t, time.Now().Add(time.Hour), p.ExpiresAt, time.Minute)
	require.Equal(t, "PENDING", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, p.RevertID))
	require.Equal(t, 1, count(t, a.Conn, `SELECT count(seq)::int FROM basalt_meta.agent_ledger WHERE kind = 'REVERT_PENDING'`))
	require.Nil(t, guardVerify(t, d))
}

func TestPrepareNothingToRevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "One change")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 84`))
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 84`)
	_, err := guard.PrepareRevert(ctx, a.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo")
	requireCode(t, err, guardmodel.CodeNothingToRevert)
	_, err = guard.PrepareRevert(ctx, a.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "")
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
}

// TestPrepareBatchedAboveOneCall: up to revert.MaxLines lines a revert is
// applied in one call, as in M3; one line more makes it a batched plan
// (decision N12-1). There is no cap.
func TestPrepareBatchedAboveOneCall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.items (id int PRIMARY KEY, v text)`)
	items := []string{"public.items"}
	a := d.NewAgent(t, "bot", items, items)
	ctx := context.Background()
	in := newRun(t, a, "Load items ten at a time")
	stmts := make([]string, 0, revert.MaxLines/10)
	for i := 0; i < revert.MaxLines; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO public.items SELECT g, 'v' FROM generate_series(%d, %d) g`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, stmts...))
	scope := action.Scope{Kind: revert.ScopeRun, ID: in.RunID}
	oneCall, err := guard.PrepareRevert(ctx, a.Conn, scope, "Undo")
	require.NoError(t, err)
	require.False(t, oneCall.Batched)
	require.Len(t, oneCall.Lines, revert.MaxLines)
	require.NotContains(t, oneCall.BindingText, "batched")

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `INSERT INTO public.items VALUES (5000, 'v')`))
	batched, err := guard.PrepareRevert(ctx, a.Conn, scope, "Undo")
	require.NoError(t, err)
	require.True(t, batched.Batched)
	require.Len(t, batched.Lines, revert.MaxLines)
	b, err := revert.ParseBinding(batched.BindingText)
	require.NoError(t, err)
	require.Equal(t, revert.MaxLines+1, b.Rows)
}

// A table that turned RLS on after the last basalt init has no guard
// policy yet: the revert cannot see the row and skips it rather than
// restore nothing, and coverage names the table until the next init.
func TestRevertRLSWithoutGuardPolicySkipped(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	d.Exec(t, fmt.Sprintf(`ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		CREATE POLICY agents_all ON public.leads TO %s USING (true) WITH CHECK (true)`, d.Names.Agents()))
	in := newRun(t, a, "Edit under RLS")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 85`))
	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 1)
	require.Equal(t, revert.ConflictRowGone, conflictOf(lines[0]))
	uncovered, err := guard.UncoveredTables(context.Background(), a.Conn)
	require.NoError(t, err)
	require.Len(t, uncovered, 1)
	require.Equal(t, "RLS_WITHOUT_GUARD_POLICY", uncovered[0].Why)
}

func TestAgentCannotUseRevertPath(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	for _, sql := range []string{
		`INSERT INTO basalt_meta.revert_running (tx, agent, change_id) VALUES (pg_current_xact_id(), current_user, gen_random_uuid())`,
		`SELECT basalt_meta._revert_execute('{}')`,
		`SELECT basalt_meta._revert_write(NULL::basalt_meta.revert_item)`,
		`SELECT * FROM basalt_meta.reverts`,
	} {
		_, err := a.Conn.Exec(ctx, sql)
		require.Equal(t, "42501", guardtest.SQLState(err), sql)
	}
	// Twelve rows in one statement is still held for the agent: nothing it
	// can set turns its own write into a revert write.
	in := newRun(t, a, "Try a big write")
	err := guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 1 WHERE id BETWEEN 1 AND 12`)
	requireCode(t, err, guardmodel.CodeApprovalRequired)
}
