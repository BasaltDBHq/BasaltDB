package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// setDatabaseDefault sets session_replication_role for every new session
// in the test database, as a person (or a tool) might with ALTER DATABASE.
func setDatabaseDefault(t *testing.T, d *guardtest.DB, value string) {
	t.Helper()
	// Plain SQL: fixture DDL on the test database's own name.
	d.Exec(t, `DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET session_replication_role = `+value+`', current_database()); END $$`)
}

// With the database default at replica, a trigger enabled the default way
// (ENABLE, origin and local only) does not fire. The guard's triggers are
// ENABLE ALWAYS, so an agent's writes are still refused, held and checked
// at commit.
func TestGuardTriggersFireUnderReplicaRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.scratch (id int PRIMARY KEY)`)
	a := d.NewAgent(t, "bot", []string{"public.leads", "public.scratch"}, leads)
	d.Exec(t, `GRANT TRUNCATE ON public.scratch TO `+a.Role)
	setDatabaseDefault(t, d, "replica")
	ctx := context.Background()
	c := a.Connect(t)
	require.Equal(t, "replica", scalarOf[string](t, c, `SHOW session_replication_role`))

	_, err := c.Exec(ctx, `UPDATE public.leads SET status = 'lost' WHERE id = 4`)
	requireCode(t, err, guard.CodeIntentRequired)

	in := newRun(t, a, "Under replica")
	err = guardtest.Guarded(ctx, c, in, `UPDATE public.leads SET status = 'lost' WHERE id <= 25`)
	requireCode(t, err, guard.CodeApprovalRequired)

	_, err = c.Exec(ctx, `TRUNCATE public.scratch`)
	requireCode(t, err, guard.CodeNotAllowed)

	err = pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginPreview(ctx, tx, in, guardtest.Timeout); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE public.leads SET status = 'lost' WHERE id = 5`)
		return err
	})
	requireCode(t, err, guard.CodePreviewCannotCommit)

	require.NoError(t, guardtest.Guarded(ctx, c, in, `UPDATE public.leads SET status = 'lost' WHERE id = 4`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'ROW_CHANGE' AND agent = $1 AND row_key = '{"id": 4}'::jsonb`, a.Role))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(id)::int FROM public.leads WHERE status = 'lost'`))
}

// Every trigger the guard installs is ENABLE ALWAYS: the ones attach puts
// on each guarded table and the commit check on basalt_meta.changes.
func TestEveryGuardTriggerIsEnabledAlways(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)

	// Plain SQL: a catalog query.
	rows, err := d.Admin.Query(context.Background(), `SELECT t.tgrelid::regclass::text || ' ' || t.tgname || ' ' || t.tgenabled::text
		FROM pg_trigger t WHERE NOT t.tgisinternal
		  AND (t.tgname LIKE 'basalt\_guard%' OR t.tgrelid = 'basalt_meta.changes'::regclass) ORDER BY 1`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"basalt_meta.changes at_commit A",
		"lead_notes basalt_guard A", "lead_notes basalt_guard_truncate A",
		"lead_owner basalt_guard A", "lead_owner basalt_guard_truncate A",
		"leads basalt_guard A", "leads basalt_guard_truncate A",
		"note_tags basalt_guard A", "note_tags basalt_guard_truncate A",
	}, got)
}

// Setup reads the database default of session_replication_role and warns,
// naming the fix, when it is not origin.
func TestPlanInitWarnsWhenReplicationRoleIsNotOrigin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	opts := guardmodel.InitOptions{Names: d.Names, Agent: guardmodel.AgentSpec{Name: "bot", Password: guard.NewPassword(), Write: leads, Read: leads}}

	s, err := guard.PlanInit(ctx, d.Admin, opts)
	require.NoError(t, err)
	require.Empty(t, s.Warnings)

	setDatabaseDefault(t, d, "replica")
	s, err = guard.PlanInit(ctx, d.Admin, opts)
	require.NoError(t, err)
	require.Len(t, s.Warnings, 1)
	require.Contains(t, s.Warnings[0], "session_replication_role is replica")
	require.Contains(t, s.Warnings[0], "ALTER DATABASE")
	require.Contains(t, s.Warnings[0], "RESET session_replication_role")
}
