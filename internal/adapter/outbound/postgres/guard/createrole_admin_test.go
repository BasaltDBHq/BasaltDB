package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// createRoleAdmin makes a login role that is not a superuser but has
// CREATEROLE and CREATE on the database, like Supabase's postgres, and
// connects as it.
func createRoleAdmin(t *testing.T, d *guardtest.DB) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	// Named to sort after the guard roles, so cleanup drops it last.
	admin := d.Names.Prefix + "_zadmin"
	pw := guard.NewPassword()
	d.Exec(t, `CREATE ROLE `+admin+` LOGIN CREATEROLE PASSWORD '`+pw+`'`)
	var db string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&db))
	d.Exec(t, `GRANT CREATE ON DATABASE `+pgx.Identifier{db}.Sanitize()+` TO `+admin)
	url, err := guard.AgentConnString(d.URL, admin, pw)
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestInitByCreateRoleAdmin installs the guard as an admin that is not a
// superuser but has CREATEROLE, like Supabase's postgres. From Postgres 16
// that admin is granted ADMIN on every role it creates (INHERIT and SET
// off), so it is a member of the agents group without being an agent. Its
// own writes must pass unguarded, and tables only it can write must not
// count as agent-writable.
func TestInitByCreateRoleAdmin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx := context.Background()
	conn := createRoleAdmin(t, d)

	// The admin owns the app's tables, as on Supabase.
	_, err := conn.Exec(ctx, `
		CREATE SCHEMA app;
		CREATE TABLE app.leads (id int PRIMARY KEY, status text NOT NULL);
		CREATE TABLE app.notes (id int PRIMARY KEY, lead_id int NOT NULL REFERENCES app.leads ON DELETE CASCADE);
		CREATE TABLE app.orders (id int PRIMARY KEY, total int NOT NULL);
		INSERT INTO app.leads VALUES (1, 'NEW'), (2, 'NEW');
		INSERT INTO app.orders VALUES (1, 10);`)
	require.NoError(t, err)

	agentPW := guard.NewPassword()
	s, err := guard.PlanInit(ctx, conn, guardmodel.InitOptions{
		Names: d.Names, Agent: guardmodel.AgentSpec{Name: "bot", Password: agentPW, Write: []string{"app.leads"}},
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return guard.ApplyScript(ctx, tx, s) }))

	uncovered, err := guard.UncoveredTables(ctx, conn)
	require.NoError(t, err)
	require.Empty(t, uncovered, "tables only the admin can write are not agent-writable")
	var guarded []string
	rows, err := conn.Query(ctx, `SELECT table_oid::text FROM basalt_meta.guarded_tables ORDER BY 1`)
	require.NoError(t, err)
	guarded, err = pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Equal(t, []string{"app.leads", "app.notes"}, guarded)

	// The person's own writes pass, with no intent.
	_, err = conn.Exec(ctx, `UPDATE app.leads SET status = 'WON' WHERE id = 1`)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `DELETE FROM app.leads WHERE id = 2`)
	require.NoError(t, err)

	// The agent is still guarded: a direct write without intent is refused.
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	agentURL, err := guard.AgentConnString(d.URL, role, agentPW)
	require.NoError(t, err)
	agent, err := pgdial.Connect(ctx, agentURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = agent.Close(context.Background()) })
	_, err = agent.Exec(ctx, `UPDATE app.leads SET status = 'LOST' WHERE id = 1`)
	require.Error(t, err)
	require.ErrorContains(t, err, "INTENT_REQUIRED")

	// Uninstall works for this admin too, and drops neither the admin nor
	// its tables.
	require.NoError(t, agent.Close(ctx))
	require.NoError(t, pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return guard.Uninstall(ctx, tx, d.Names) }))
	var roles, leads int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(1)::int FROM pg_roles WHERE rolname LIKE $1`, d.Names.Prefix+`\_%`).Scan(&roles))
	require.Equal(t, 1, roles, "only the admin is left")
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(id)::int FROM app.leads`).Scan(&leads))
	require.Equal(t, 1, leads)
}
