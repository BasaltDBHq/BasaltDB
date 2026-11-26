package guard_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// prepareSigned prepares a revert as the agent (the CLI's relay) and signs
// its binding with the person's passkey, as the revert page does.
func prepareSigned(t *testing.T, a *guardtest.Agent, p *passkeytest.Authenticator, kind revert.Scope, id uuid.UUID) (revertstore.PreparedRevert, passkey.Assertion) {
	t.Helper()
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, revertstore.Scope{Kind: kind, ID: id}, "Undo a bad run")
	require.NoError(t, err)
	as, err := p.Sign(approval.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return prep, as
}

// revertRun prepares, signs and applies a revert of scope.
func revertScope(t *testing.T, a *guardtest.Agent, p *passkeytest.Authenticator, kind revert.Scope, id uuid.UUID) revertstore.AppliedRevert {
	t.Helper()
	prep, as := prepareSigned(t, a, p, kind, id)
	out, err := guard.ApplyRevert(context.Background(), a.Conn, prep.RevertID, as)
	require.NoError(t, err)
	return out
}

func requireRevertInvalid(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guard.CodeRevertInvalid)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Contains(t, pg.Detail, detail)
}

// requireRevertRefused is REVERT_INVALID with the typed detail code and a
// hint that contains hint (version 11).
func requireRevertRefused(t *testing.T, err error, code, hint string) {
	t.Helper()
	requireCode(t, err, guard.CodeRevertInvalid)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Equal(t, code, pg.Detail)
	require.Contains(t, pg.Hint, hint)
}

func leadStatus(t *testing.T, d *guardtest.DB, id int) string {
	t.Helper()
	return scalarOf[string](t, d.Admin, `SELECT status FROM public.leads WHERE id = $1`, id)
}

func TestApplyRevertRestoresAndSkips(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Mark leads won")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 90 AND 95`))
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 93`)

	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, 5, out.Rows)
	require.Equal(t, 1, out.Skipped)
	for _, id := range []int{90, 91, 92, 94, 95} {
		require.Equal(t, "open", leadStatus(t, d, id))
	}
	require.Equal(t, "person", leadStatus(t, d, 93), "people win")

	require.Equal(t, "REVERT", scalarOf[string](t, a.Conn, `SELECT op FROM basalt_meta.agent_changes WHERE change_id = $1`, out.ChangeID))
	require.Equal(t, "PERSON", scalarOf[string](t, a.Conn, `SELECT actor_kind FROM basalt_meta.agent_changes WHERE change_id = $1`, out.ChangeID))
	require.Equal(t, 5, scalarOf[int](t, a.Conn, `SELECT rows FROM basalt_meta.agent_changes WHERE change_id = $1`, out.ChangeID))
	original := changeIDOf(t, a, in.RunID)
	require.Equal(t, "APPLIED", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_changes WHERE change_id = $1`, original),
		"a partly reverted change stays APPLIED")
	require.Equal(t, []uuid.UUID{out.ChangeID}, scalarOf[[]uuid.UUID](t, a.Conn,
		`SELECT reverted_by FROM basalt_meta.agent_changes WHERE change_id = $1`, original))
	require.Equal(t, 5, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE change_id = $1 AND kind = 'ROW_CHANGE'
		AND detail -> 'revertOf' ? $2`, out.ChangeID, original.String()))
	skipped := scalarOf[string](t, d.Admin, `SELECT detail -> 'skipped' ->> 0 FROM basalt_meta.ledger WHERE kind = 'REVERTED'`)
	require.JSONEq(t, `{"resource": "public.leads", "key": {"id": 93}, "conflict": "CHANGED_AFTER"}`, skipped)
	require.Equal(t, "APPLIED", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_reverts`))
	require.Nil(t, guardVerify(t, d))
}

func TestApplyRevertDeletesInsertsAndCascades(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	notes := tableDigest(t, d, "public.lead_notes")
	tags := tableDigest(t, d, "public.note_tags")
	owners := tableDigest(t, d, "public.lead_owner")
	in := newRun(t, a, "Clean up leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `INSERT INTO public.leads (id, name) VALUES (900, 'new')`))
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{5}, []string{})
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))

	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Zero(t, out.Skipped)
	require.Zero(t, count(t, d.Admin, `SELECT count(id)::int FROM public.leads WHERE id IN (900, 9101)`))
	require.Equal(t, "lead 5", scalarOf[string](t, d.Admin, `SELECT name FROM public.leads WHERE id = 5`))
	require.Equal(t, notes, tableDigest(t, d, "public.lead_notes"), "cascaded notes restored")
	require.Equal(t, tags, tableDigest(t, d, "public.note_tags"), "cascaded tags restored")
	require.Equal(t, owners, tableDigest(t, d, "public.lead_owner"), "SET NULL undone")
	require.Zero(t, count(t, a.Conn, `SELECT count(change_id)::int FROM basalt_meta.agent_changes
		WHERE run_id = $1 AND op <> 'READ' AND status <> 'REVERTED'`, in.RunID), "every change fully reverted")
	require.Nil(t, guardVerify(t, d))
}

// Revert bypasses the row limits (D6): 60 rows written ten at a time come
// back in one revert.
func TestApplyBypassesRowLimits(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	before := tableDigest(t, d, "public.leads")
	in := newRun(t, a, "Loop of small writes")
	for i := range 6 {
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
			fmt.Sprintf(`UPDATE public.leads SET score = 99 WHERE id BETWEEN %d AND %d`, i*10+1, i*10+10)))
	}
	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, 60, out.Rows)
	require.Equal(t, before, tableDigest(t, d, "public.leads"))
}

func TestRevertRoundTripsTypes(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TYPE public.mood AS ENUM ('calm', 'busy');
		CREATE TABLE public.kinds (
		    id      bigint PRIMARY KEY,
		    at      timestamptz,
		    amount  numeric(12, 3),
		    ratio   float8,
		    raw     bytea,
		    tags    text[],
		    mood    public.mood,
		    doc     json,
		    docb    jsonb,
		    day     date,
		    note    text,
		    flag    boolean,
		    big     bigint);
		INSERT INTO public.kinds VALUES (1, '2026-11-10 06:02:11.123456+07', 12.500, 0.1, '\xdeadbeef', '{a,"b c",NULL}',
		    'calm', '{"x": [1, 2.50]}', '{"y": null}', '2026-02-28', 'Café ✓ — 日本', true, 9007199254740993),
		    (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)`)
	kinds := []string{"public.kinds"}
	a := d.NewAgent(t, "bot", kinds, kinds)
	p := person(t, d)
	before := tableDigest(t, d, "public.kinds")
	in := newRun(t, a, "Overwrite every column")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.kinds SET at = now(), amount = 1, ratio = 2,
		raw = '\x00', tags = '{}', mood = 'busy', doc = '[]', docb = '[]', day = '2000-01-01', note = 'x', flag = false, big = 1`))
	revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, before, tableDigest(t, d, "public.kinds"))
}

func TestRevertGeneratedAndIdentityColumns(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.counters (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, a int NOT NULL,
		    doubled int GENERATED ALWAYS AS (a * 2) STORED);
		INSERT INTO public.counters (a) VALUES (1), (2), (3)`)
	counters := []string{"public.counters"}
	a := d.NewAgent(t, "bot", counters, counters)
	p := person(t, d)
	before := tableDigest(t, d, "public.counters")
	in := newRun(t, a, "Drop a counter")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.counters SET a = 10 WHERE id = 1`))
	approvedWrite(t, a, p, in, `DELETE FROM public.counters WHERE id = $1`, []any{2}, []string{})
	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, 2, out.Rows)
	require.Equal(t, before, tableDigest(t, d, "public.counters"), "same identity value, generated column recomputed")
}

// A row that changes after the preview fails the whole revert: the
// signature covers the rows as shown.
func TestApplyRefusedWhenRowChangedAfterPreview(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Two leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id IN (110, 111)`))
	prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 111`)

	_, err := guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	requireRevertRefused(t, err, guard.RevertRowsChanged, "rows changed since the preview")
	require.Equal(t, "won", leadStatus(t, d, 110), "nothing was written")
	require.Equal(t, "PENDING", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_reverts`))
}

func TestApplyRefusals(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "One lead")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 120`))
	prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)

	t.Run("the agent signs with its own key", func(t *testing.T) {
		forger, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		forger.ID = p.ID
		forged, err := forger.Sign(approval.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = guard.ApplyRevert(ctx, a.Conn, prep.RevertID, forged)
		requireRevertInvalid(t, err, "bad passkey signature")
	})
	t.Run("a signature over another binding", func(t *testing.T) {
		other, err := p.Sign(approval.Challenge(prep.BindingText+" "), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = guard.ApplyRevert(ctx, a.Conn, prep.RevertID, other)
		requireRevertInvalid(t, err, "client data does not match")
	})
	t.Run("an unknown revert", func(t *testing.T) {
		_, err := guard.ApplyRevert(ctx, a.Conn, uuid.Must(uuid.NewV7()), as)
		requireRevertInvalid(t, err, "no such revert")
	})
	t.Run("a superuser relay", func(t *testing.T) {
		_, err := guard.ApplyRevert(ctx, d.Admin, prep.RevertID, as)
		requireCode(t, err, guard.CodeNotAllowed)
	})

	_, err := guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	requireRevertRefused(t, err, guard.RevertAlreadyApplied, "already applied")

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, newRun(t, a, "Another"), `UPDATE public.leads SET status = 'won' WHERE id = 121`))
	late, lateAs := prepareSigned(t, a, p, revert.ScopeChange,
		scalarOf[uuid.UUID](t, a.Conn, `SELECT change_id FROM basalt_meta.agent_changes WHERE op = 'UPDATE' ORDER BY change_id DESC LIMIT 1`))
	d.Exec(t, `UPDATE basalt_meta.reverts SET expires_at = now() - interval '1 second' WHERE revert_id = $1`, late.RevertID)
	_, err = guard.ApplyRevert(ctx, a.Conn, late.RevertID, lateAs)
	requireCode(t, err, guard.CodeRevertExpired)
}

func TestRevertOfRevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Win two leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id IN (130, 131)`))
	first := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, "open", leadStatus(t, d, 130))

	again := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	for _, l := range again {
		require.Equal(t, revert.ConflictAlreadyReverted, conflictOf(l))
	}
	_, err := guard.PrepareRevert(ctx, a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo again")
	requireCode(t, err, guard.CodeNothingToRevert)

	undo := revertScope(t, a, p, revert.ScopeChange, first.ChangeID)
	require.Equal(t, 2, undo.Rows)
	require.Equal(t, "won", leadStatus(t, d, 130), "the revert of the revert brings the agent's values back")
	require.Equal(t, "REVERTED", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_changes WHERE change_id = $1`, first.ChangeID))
	require.Nil(t, guardVerify(t, d))
}

// The run that wrote a reverted row still knows the version it left, so
// its next write to that row is refused: it has to read the row again.
func TestStaleReadAfterRevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Win a lead")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 140`))
	revertScope(t, a, p, revert.ScopeRun, in.RunID)
	err := guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won again' WHERE id = 140`)
	requireCode(t, err, guard.CodeStaleRead)
}

func TestAppTriggerRunsOnRevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.docs (id int PRIMARY KEY, body text, updated_at timestamptz NOT NULL DEFAULT now());
		CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN NEW.updated_at := clock_timestamp(); RETURN NEW; END $$;
		CREATE TRIGGER touch BEFORE UPDATE ON public.docs FOR EACH ROW EXECUTE FUNCTION public.touch();
		INSERT INTO public.docs VALUES (1, 'first', '2026-01-01')`)
	docs := []string{"public.docs"}
	a := d.NewAgent(t, "bot", docs, docs)
	p := person(t, d)
	in := newRun(t, a, "Edit a doc")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.docs SET body = 'second' WHERE id = 1`))
	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Equal(t, 1, out.Rows)
	require.Equal(t, "first", scalarOf[string](t, d.Admin, `SELECT body FROM public.docs WHERE id = 1`))
}

func TestPruneRevertValues(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Win a lead")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 150`))
	_, err := guard.PrepareRevert(context.Background(), a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo")
	require.NoError(t, err)
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '31 days')`)
	require.Zero(t, count(t, d.Admin, `SELECT count(revert_id)::int FROM basalt_meta.reverts WHERE lines IS NOT NULL OR binding_text IS NOT NULL`))
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	require.Zero(t, count(t, d.Admin, `SELECT count(revert_id)::int FROM basalt_meta.reverts`))
}
