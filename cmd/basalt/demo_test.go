package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

func demoInit(t *testing.T, d *guardtest.DB, config string, extra ...string) result {
	t.Helper()
	args := append([]string{"init", "--demo", "--prefix", d.Names.Prefix, "--config", config, "--os-user", "tester", "--skip-passkey"}, extra...)
	return cli(t, map[string]string{envAdminURL: d.URL}, "", args...)
}

func TestInitDemoUsageErrors(t *testing.T) {
	t.Parallel()
	for _, extra := range [][]string{{"--write", "public.x"}, {"--read", "public.x"}} {
		r := cli(t, nil, "", append([]string{"init", "--demo"}, extra...)...)
		require.Equal(t, exitUsage, r.code, r.stderr)
	}
}

func TestInitDemoCreatesAndGuardsOnlyTheSample(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.mine (id integer PRIMARY KEY, v text); INSERT INTO public.mine VALUES (1, 'a')`)
	config := tempConfig(t)
	ctx := context.Background()

	r := demoInit(t, d, config, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "CREATE SCHEMA basalt_demo")
	var n int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_namespace WHERE nspname IN ('basalt_demo', 'basalt_meta')`).Scan(&n))
	require.Zero(t, n, "a dry run changes nothing")

	r = demoInit(t, d, config, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt: demo ready: leads 30, lead_notes 20")
	cred := filepath.Join(filepath.Dir(config), "agents", "demo_bot.url")

	require.Equal(t, 30, agentRows(t, cred, "basalt_demo.leads"))
	require.Equal(t, 20, agentRows(t, cred, "basalt_demo.lead_notes"))
	// The demo agent cannot read the person's table.
	b, err := os.ReadFile(cred)
	require.NoError(t, err)
	ac, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer ac.Close(ctx)
	_, err = ac.Exec(ctx, `SELECT id FROM public.mine`)
	require.Equal(t, "42501", guardtest.SQLState(err))

	// Nothing outside basalt_demo was granted to the agent.
	var granted int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM information_schema.role_table_grants
		WHERE grantee = $1 AND table_schema <> 'basalt_demo'`, d.Names.Prefix+"_agent_demo_bot").Scan(&granted))
	require.Zero(t, granted)
	var guarded int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		WHERE c.relname = 'mine' AND NOT t.tgisinternal`).Scan(&guarded))
	require.Zero(t, guarded, "public.mine is not guarded")
}

func TestInitDemoTwiceKeepsEdits(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	config := tempConfig(t)
	r := demoInit(t, d, config, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	d.Exec(t, `UPDATE basalt_demo.leads SET status = 'WON' WHERE id = 2; DELETE FROM basalt_demo.lead_notes WHERE id = 1`)

	r = demoInit(t, d, config, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt: sample schema basalt_demo already exists; its rows are left as they are")
	require.Contains(t, r.stderr, "basalt: demo ready: leads 30, lead_notes 19")
	var status string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT status FROM basalt_demo.leads WHERE id = 2`).Scan(&status))
	require.Equal(t, "WON", status)
}

func TestInitDemoLeavesAnExistingTableAlone(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE SCHEMA basalt_demo;
		CREATE TABLE basalt_demo.leads (id integer PRIMARY KEY, name text);
		INSERT INTO basalt_demo.leads SELECT i, 'mine' FROM generate_series(1, 10) AS i;
		ALTER TABLE basalt_demo.leads ENABLE ROW LEVEL SECURITY`)
	r := demoInit(t, d, tempConfig(t), "--yes", "--agent-rls", "none")
	require.Equal(t, exitOK, r.code, r.stderr)
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

func TestMissingDemoTablesSuggestInitDemo(t *testing.T) {
	t.Parallel()
	err := missingTablesHint(&guard.MissingTablesError{Tables: []string{"basalt_demo.leads"}}, "db")
	require.Contains(t, err.Error(), "basalt init --demo")
}

// A sample table the guard cannot key (here the person's own basalt_demo
// tables, without a primary key) fails init --demo with the guard's detail
// and hint, as plain init shows them.
func TestInitDemoShowsTheGuardsDetailAndHint(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE SCHEMA basalt_demo;
		CREATE TABLE basalt_demo.leads (id integer, name text);
		CREATE TABLE basalt_demo.lead_notes (id integer, lead_id integer, body text)`)
	r := demoInit(t, d, tempConfig(t), "--yes", "--no-service")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "NOT_ALLOWED")
	require.Contains(t, r.stderr, "has no primary key; the guard keys ledger rows by it.")
	require.Contains(t, r.stderr, "add a primary key, or revoke the agent's write privileges on it.")
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v, "the transaction rolled back")
}
