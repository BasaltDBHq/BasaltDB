package setup_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// fixtureOn is newFixture on database d with a config of its own, as a
// second engine installing the demo there.
func fixtureOn(t *testing.T, d *guardtest.DB) *fixture {
	t.Helper()
	f := &fixture{db: d, config: filepath.Join(t.TempDir(), "engine.json"), now: time.Now()}
	svc, err := setup.NewLocal(setup.LocalOptions{
		Backend:    setupbackend.Backend{},
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: d.Names.Prefix,
		Now: func() time.Time { return f.now },
	})
	require.NoError(t, err)
	f.svc = svc
	return f
}

// installDemo runs the demo install on f's page for agent (demo_bot when
// ""): the check, a passkey when the database has none, then the run. It
// returns the run's lines.
func installDemo(t *testing.T, f *fixture, agent string) []string {
	t.Helper()
	ctx := context.Background()
	req := f.request()
	if agent != "" {
		req.Agent = agent
	}
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	if checked.PasskeyNeeded {
		req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	}
	done, err := f.svc.Run(ctx, req)
	require.NoError(t, err)
	return done.Lines
}

// The demo guards only the sample: the demo agent cannot read the person's
// own table, gets no grant outside basalt_demo, and the person's table
// gets no trigger.
func TestDemoInstallGuardsOnlyTheSample(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	d := f.db
	ctx := context.Background()
	d.Exec(t, `CREATE TABLE public.mine (id integer PRIMARY KEY, v text); INSERT INTO public.mine VALUES (1, 'a')`)

	require.Equal(t, []string{"demo ready: leads 30, lead_notes 20"}, installDemo(t, f, ""))
	dsn, err := config.ReadCredential(filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url"))
	require.NoError(t, err)
	ac, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer ac.Close(ctx)
	_, err = ac.Exec(ctx, `SELECT id FROM public.mine`)
	require.Equal(t, "42501", guardtest.SQLState(err), "the demo agent cannot read the person's table")

	var granted int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM information_schema.role_table_grants
		WHERE grantee = $1 AND table_schema <> 'basalt_demo'`, d.Names.Prefix+"_agent_demo_bot").Scan(&granted))
	require.Zero(t, granted, "nothing outside basalt_demo is granted to the agent")
	var guarded int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		WHERE c.relname = 'mine' AND NOT t.tgisinternal`).Scan(&guarded))
	require.Zero(t, guarded, "public.mine is not guarded")
}

// A second demo install, for another agent, keeps the rows the person
// changed.
func TestDemoInstallAgainKeepsEdits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	installDemo(t, f, "")
	f.db.Exec(t, `UPDATE basalt_demo.leads SET status = 'WON' WHERE id = 2; DELETE FROM basalt_demo.lead_notes WHERE id = 1`)

	// Another engine's agent: an install never takes over a role.
	second := fixtureOn(t, f.db)
	req := second.request()
	req.Agent = "demo_two"
	checked, err := second.svc.Check(context.Background(), req)
	require.NoError(t, err)
	require.Contains(t, checked.Notes, "sample schema basalt_demo already exists; its rows are left as they are")
	lines := installDemo(t, second, "demo_two")
	require.Contains(t, lines, "demo ready: leads 30, lead_notes 19")
	var status string
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT status FROM basalt_demo.leads WHERE id = 2`).Scan(&status))
	require.Equal(t, "WON", status)
}

// A basalt_demo table the person made is left as it is: its rows, its
// row-level security and its indexes.
func TestDemoInstallLeavesAnExistingTableAlone(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	d := f.db
	d.Exec(t, `CREATE SCHEMA basalt_demo;
		CREATE TABLE basalt_demo.leads (id integer PRIMARY KEY, name text);
		INSERT INTO basalt_demo.leads SELECT i, 'mine' FROM generate_series(1, 10) AS i;
		ALTER TABLE basalt_demo.leads ENABLE ROW LEVEL SECURITY`)
	installDemo(t, f, "")
	ctx := context.Background()
	var rls bool
	var leads, notes int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT relrowsecurity FROM pg_class WHERE oid = 'basalt_demo.leads'::regclass`).Scan(&rls))
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM basalt_demo.leads)::int, (SELECT count(*) FROM basalt_demo.lead_notes)::int`).Scan(&leads, &notes))
	require.True(t, rls, "row-level security on the person's table is left as it was")
	require.Equal(t, 10, leads, "no demo row is added to the existing table")
	require.Equal(t, 20, notes)
	var idx int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(*)::int FROM pg_indexes WHERE schemaname = 'basalt_demo' AND tablename = 'leads'`).Scan(&idx))
	require.Equal(t, 1, idx, "only its primary key")
}
