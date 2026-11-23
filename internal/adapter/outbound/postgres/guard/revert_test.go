package guard_test

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// previewRevert returns the parsed revert lines of a scope, checking each
// one parses with the Go codec and the text is in COLLATE "C" order.
func previewRevert(t *testing.T, q guard.Querier, kind revert.Scope, id uuid.UUID) []revert.Line {
	t.Helper()
	texts, err := guard.PreviewRevert(context.Background(), q, action.Scope{Kind: kind, ID: id})
	detail, hint, _ := guard.ScopeRefusal(err)
	require.NoError(t, err, "%s: %s", detail, hint)
	require.True(t, sort.StringsAreSorted(texts), "lines must be in byte order")
	out := make([]revert.Line, 0, len(texts))
	for _, s := range texts {
		l, err := revert.ParseLine(s)
		require.NoError(t, err, s)
		out = append(out, l)
	}
	return out
}

// lineFor finds the line of table with key (compact JSON); redacted lines
// have no key and are found by table only when key is "".
func lineFor(t *testing.T, lines []revert.Line, table, key string) revert.Line {
	t.Helper()
	for _, l := range lines {
		if l.Table != table {
			continue
		}
		if key == "" || (len(l.Key) > 0 && compact(t, l.Key) == key) {
			return l
		}
	}
	require.Failf(t, "no line", "%s %s in %+v", table, key, lines)
	return revert.Line{}
}

func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func field(t *testing.T, raw json.RawMessage, name string) any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m[name]
}

// requireScopeRefused checks err is SCOPE_REFUSED (BS011) with detail.
func requireScopeRefused(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guardmodel.CodeScopeRefused)
	got, _, ok := guard.ScopeRefusal(err)
	require.True(t, ok)
	require.Equal(t, detail, got, err.Error())
}

func conflictOf(l revert.Line) string {
	if l.Conflict == nil {
		return ""
	}
	return *l.Conflict
}

// approvedWrite holds stmt, signs it with the person's passkey, relays it
// and applies it, as the engine does for a held write.
func approvedWrite(t *testing.T, a *guardtest.Agent, p *passkeytest.Authenticator, in guard.Intent, stmt string, params []any, assigned []string) {
	t.Helper()
	ctx := context.Background()
	held, _ := previewAndHold(t, a.Conn, in, stmt, params, assigned)
	_, err := guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	require.NoError(t, err)
	require.NoError(t, applyApproved(ctx, a.Conn, in, held.ApprovalID, stmt, params))
}

func changeIDOf(t *testing.T, a *guardtest.Agent, run uuid.UUID) uuid.UUID {
	t.Helper()
	return scalarOf[uuid.UUID](t, a.Conn, `SELECT change_id FROM basalt_meta.agent_changes
		WHERE run_id = $1 AND op <> 'SELECT' ORDER BY change_id LIMIT 1`, run)
}

func TestRevertLinesUpdate(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Mark leads won")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id IN (8, 9)`))

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 2)
	for _, l := range lines {
		require.Equal(t, revert.ActionRestore, l.Action)
		require.Equal(t, "UPDATE", l.Op)
		require.Equal(t, "public.leads", l.Table)
		require.Equal(t, "open", field(t, l.Set, "status"))
		require.Equal(t, "won", field(t, l.Now, "status"))
		require.Len(t, l.ChangeIDs, 1)
		require.False(t, l.Cascaded)
	}
	byChange := previewRevert(t, a.Conn, revert.ScopeChange, lines[0].ChangeIDs[0])
	require.Len(t, byChange, 2, "the run is one change")

	got, err := guard.PreviewRevert(ctx, a.Conn, action.Scope{Kind: revert.ScopeRun, ID: uuid.Must(uuid.NewV7())})
	require.Empty(t, got)
	requireScopeRefused(t, err, guardmodel.ScopeNotOwnRun)
	_, err = guard.PreviewRevert(ctx, d.Admin, action.Scope{Kind: revert.ScopeRun, ID: in.RunID})
	requireCode(t, err, guardmodel.CodeNotAllowed)
}

func TestRevertLinesInsertDeleteAndNetNoOp(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Tidy leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
		`INSERT INTO public.leads (id, name) VALUES (900, 'new'), (901, 'temporary')`))
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{901}, []string{})
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{5}, []string{})

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	inserted := lineFor(t, lines, "public.leads", `{"id":900}`)
	require.Equal(t, "DELETE", inserted.Op, "an inserted row is deleted")
	require.Nil(t, inserted.Conflict)
	require.Equal(t, "null", string(inserted.Set))

	deleted := lineFor(t, lines, "public.leads", `{"id":5}`)
	require.Equal(t, "INSERT", deleted.Op, "a deleted row is re-inserted")
	require.JSONEq(t, `{"id": 5, "name": "lead 5", "status": "open", "score": 5}`, string(deleted.Set))
	require.Equal(t, "null", string(deleted.Now))

	for _, l := range lines {
		require.NotContains(t, string(l.Key), "901", "inserted and deleted in scope: no line")
	}
	// Lead 5's notes 9 and 10 and tags 9 and 10 were cascaded deletes of a
	// table the agent cannot read.
	cascaded := 0
	for _, l := range lines {
		if l.Cascaded {
			cascaded++
			require.True(t, l.Redacted)
			require.Equal(t, "INSERT", l.Op)
		}
	}
	require.Equal(t, 4, cascaded)
	require.Len(t, lines, 6)
}

func TestRevertLinesTwoUpdatesOneLine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Score a lead")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
		`UPDATE public.leads SET score = 50 WHERE id = 30`, `UPDATE public.leads SET score = 60 WHERE id = 30`))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 30`))

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 1)
	l := lines[0]
	require.Nil(t, l.Conflict)
	require.JSONEq(t, `{"id": 30, "name": "lead 30", "status": "open", "score": 2}`, string(l.Set),
		"restores the row before the first change")
	require.Len(t, l.ChangeIDs, 3)
}

func TestRevertFollowsKeyChange(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Renumber a lead")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET name = 'renamed' WHERE id = 9101`))

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 2)
	lead := lineFor(t, lines, "public.leads", `{"id":9101}`)
	require.Equal(t, "UPDATE", lead.Op)
	require.Nil(t, lead.Conflict)
	require.EqualValues(t, 101, field(t, lead.Set, "id"))
	require.Equal(t, "lead 101", field(t, lead.Set, "name"))
	owner := lineFor(t, lines, "public.lead_owner", "")
	require.True(t, owner.Cascaded, "ON UPDATE SET NULL reached lead_owner 1")
	require.True(t, owner.Redacted)
	require.Equal(t, revert.ActionRestore, owner.Action)
}

func TestRevertCompositeKey(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.pairs (a int, b int, v text NOT NULL, PRIMARY KEY (a, b));
		INSERT INTO public.pairs VALUES (1, 2, 'x'), (1, 3, 'y')`)
	pairs := []string{"public.pairs"}
	a := d.NewAgent(t, "bot", pairs, pairs)
	in := newRun(t, a, "Edit a pair")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.pairs SET v = 'z' WHERE a = 1 AND b = 2`))
	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 1)
	require.Equal(t, `{"a":1,"b":2}`, compact(t, lines[0].Key))
	require.Nil(t, lines[0].Conflict)
}

// People win: every way a row can change after the agent is a SKIP with
// its reason; the rest still restores.
func TestRevertConflicts(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Bulk status change")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 40 AND 45`))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9047 WHERE id = 47`))
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{46}, []string{})

	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 40`)              // a person edits
	d.Exec(t, `UPDATE public.leads SET status = status WHERE id = 41`)                // a person saves without changing
	d.Exec(t, `DELETE FROM public.leads WHERE id = 42`)                               // a person deletes
	d.Exec(t, `INSERT INTO public.leads (id, name) VALUES (46, 'person re-created')`) // the deleted key is taken
	d.Exec(t, `INSERT INTO public.leads (id, name) VALUES (47, 'person took the old key')`)

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	want := map[string]string{
		`{"id":40}`:   revert.ConflictChangedAfter,
		`{"id":41}`:   revert.ConflictChangedAfter,
		`{"id":42}`:   revert.ConflictRowGone,
		`{"id":43}`:   "",
		`{"id":44}`:   "",
		`{"id":45}`:   "",
		`{"id":46}`:   revert.ConflictKeyTaken,
		`{"id":9047}`: revert.ConflictKeyTaken,
	}
	for key, conflict := range want {
		l := lineFor(t, lines, "public.leads", key)
		require.Equal(t, conflict, conflictOf(l), key)
		if conflict == "" {
			require.Equal(t, revert.ActionRestore, l.Action, key)
			continue
		}
		require.Equal(t, revert.ActionSkip, l.Action, key)
	}
}

func TestRevertConflictValuesPruned(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Old change")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 50`))
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '31 days')`)
	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 1)
	require.Equal(t, revert.ConflictValuesPruned, conflictOf(lines[0]))
}

func TestRevertConflictSchemaChanged(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Two changes")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 51`))

	d.Exec(t, `ALTER TABLE public.leads ADD COLUMN region text DEFAULT 'eu'`)
	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Nil(t, lines[0].Conflict, "an added column does not conflict")

	d.Exec(t, `ALTER TABLE public.leads DROP COLUMN score`)
	lines = previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Equal(t, revert.ConflictSchemaChanged, conflictOf(lines[0]))
}

func TestRevertTaskScopeAcrossAgents(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	b := d.NewAgent(t, "helper", leads, leads)
	ctx := context.Background()
	task := uuid.Must(uuid.NewV7())
	inA := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "first half"}
	inB := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "second half"}
	require.NoError(t, guard.StartRun(ctx, a.Conn, inA))
	require.NoError(t, guard.StartRun(ctx, b.Conn, inB))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, inA, `UPDATE public.leads SET status = 'a' WHERE id = 60`))
	require.NoError(t, guardtest.Guarded(ctx, b.Conn, inB, `UPDATE public.leads SET status = 'b' WHERE id = 60`))

	run := previewRevert(t, a.Conn, revert.ScopeRun, inA.RunID)
	require.Equal(t, revert.ConflictChangedAfter, conflictOf(run[0]), "the other agent wrote it after")

	// A person writes lead 61 between the two agents' writes: the task's
	// chain is broken, so the row is skipped even though it ends as the
	// second agent left it.
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, inA, `UPDATE public.leads SET status = 'a' WHERE id = 61`))
	d.Exec(t, `UPDATE public.leads SET name = 'person between' WHERE id = 61`)
	require.NoError(t, guardtest.Guarded(ctx, b.Conn, inB, `UPDATE public.leads SET status = 'b' WHERE id = 61`))

	// A task proposal holds only the caller's own lines (RS-1): lead 60 is
	// skipped as changed after, since the other agent wrote it later, and
	// lead 61 for the person's write between.
	own := previewRevert(t, a.Conn, revert.ScopeTask, task)
	require.Len(t, own, 2)
	for _, l := range own {
		require.Equal(t, revert.ConflictChangedAfter, conflictOf(l))
		require.Len(t, l.ChangeIDs, 1, "only bot's own change")
	}
	theirs := previewRevert(t, b.Conn, revert.ScopeTask, task)
	require.Len(t, theirs, 2)
	lead60 := lineFor(t, theirs, "public.leads", `{"id":60}`)
	require.Nil(t, lead60.Conflict)
	require.Equal(t, "a", field(t, lead60.Set, "status"), "the other agent's revert goes back to what bot left")
	require.Len(t, lead60.ChangeIDs, 1)
}
