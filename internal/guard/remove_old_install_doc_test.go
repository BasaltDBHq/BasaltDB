package guard_test

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// docSQL is the SQL blocks of docs/remove-old-install.md, in order.
func docSQL(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/remove-old-install.md")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```sql\n(.*?)```").FindAllStringSubmatch(string(raw), -1)
	out := make([]string, 0, len(blocks))
	for _, m := range blocks {
		out = append(out, m[1])
	}
	require.Len(t, out, 3, "the list, the removal and the check")
	return out
}

// The removal SQL of docs/remove-old-install.md, run as an admin that is
// not a superuser but has CREATEROLE (like Supabase's postgres), removes
// an install with its agent, leaves the person's table, and a new install
// on the same database then succeeds.
func TestTheRemoveOldInstallDocSQLRemovesAnInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx := context.Background()
	conn := createRoleAdmin(t, d)
	_, err := conn.Exec(ctx, `CREATE SCHEMA app;
		CREATE TABLE app.leads (id int PRIMARY KEY, status text NOT NULL);
		ALTER TABLE app.leads ENABLE ROW LEVEL SECURITY;
		INSERT INTO app.leads VALUES (1, 'NEW'), (2, 'NEW');`)
	require.NoError(t, err)
	install := func() {
		spec := guard.AgentSpec{Name: "demo_bot", Password: guard.NewPassword(), Write: []string{"app.leads"}}
		blind, err := guard.AgentBlindTables(ctx, conn, d.Names, spec)
		require.NoError(t, err)
		require.NotEmpty(t, blind, "the agent gets a row-level security policy, which the removal drops")
		s, err := guard.PlanInit(ctx, conn, guard.InitOptions{Names: d.Names, Agent: spec, AgentPolicies: blind})
		require.NoError(t, err)
		require.NoError(t, pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return s.Apply(ctx, tx) }))
	}
	install()

	role, err := d.Names.Agent("demo_bot")
	require.NoError(t, err)
	ours := strings.NewReplacer(
		"basalt_agent_demo_bot", role, `basalt\_agent\_%`, strings.ReplaceAll(d.Names.Prefix, "_", `\_`)+`\_agent\_%`,
		"basalt_agents", d.Names.Agents(), "basalt_guard", d.Names.Guard(), "'basalt%'", "'"+d.Names.Prefix+"%'",
	)
	blocks := docSQL(t)
	rolesOf := func(sql string) []string {
		rows, err := conn.Query(ctx, ours.Replace(sql))
		require.NoError(t, err)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return names
	}
	require.Equal(t, []string{role}, rolesOf(blocks[0]), "the list names the agent role")

	_, err = conn.Exec(ctx, ours.Replace(blocks[1]))
	require.NoError(t, err)
	var left []string
	for _, r := range rolesOf(blocks[2]) {
		if r != d.Names.Prefix+"_zadmin" { // the test's own admin
			left = append(left, r)
		}
	}
	require.Empty(t, left, "no BasaltDB role is left")
	var schema, rows int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM pg_namespace WHERE nspname = 'basalt_meta'`).Scan(&schema))
	require.Zero(t, schema)
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM app.leads`).Scan(&rows))
	require.Equal(t, 2, rows, "the person's rows stay")

	install()
}
