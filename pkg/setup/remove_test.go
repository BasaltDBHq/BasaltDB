package setup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

func schemaExists(t *testing.T, d *guardtest.DB, schema string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)`, schema).Scan(&ok))
	return ok
}

func prefixRoles(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT count(*)::int FROM pg_catalog.pg_roles WHERE starts_with(rolname, $1)`, d.Names.Prefix+"_").Scan(&n))
	return n
}

func removeCode(t *testing.T, err error) string {
	t.Helper()
	var se *setup.Error
	require.True(t, errors.As(err, &se), "%v", err)
	return se.Code
}

// The removal needs only the admin connection: it lists the bots by name,
// shows the SQL, and drops the guard, every bot role and the sample schema
// once the typed name is the database's.
func TestRemoveWithTheAdminConnectionOnly(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx := context.Background()
	// The sample schema, as the sample-database setup makes it.
	tx, err := d.Admin.Begin(ctx)
	require.NoError(t, err)
	_, err = demo.Seed(ctx, tx)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	d.NewAgent(t, "sales_bot", []string{demo.Tables[0]}, nil)
	d.NewAgent(t, "ops_bot", nil, demo.Tables)

	r, err := setup.CheckRemove(ctx, d.Admin)
	require.NoError(t, err)
	var database string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	require.Equal(t, database, r.Database)
	require.Equal(t, []string{"ops_bot", "sales_bot"}, r.Bots)
	require.False(t, r.NothingToRemove)
	require.True(t, r.SampleSchema, "the sample schema is dropped too")
	require.Contains(t, r.SQL, "DROP SCHEMA IF EXISTS basalt_meta CASCADE;")
	require.Contains(t, r.SQL, "DROP ROLE ")
	require.Contains(t, r.SQL, "DROP TABLE basalt_demo.leads;")
	require.NotContains(t, r.SQL, "basalt_demo CASCADE", "the sample schema is dropped without CASCADE")
	require.Contains(t, r.Lines[1], "ops_bot, sales_bot")
	require.True(t, schemaExists(t, d, "basalt_meta"), "check changes nothing")

	// A typed name that is not the database's changes nothing.
	for _, typed := range []string{"", database + "x", "postgres", string(make([]byte, 64))} {
		_, err = setup.RunRemove(ctx, d.Admin, typed)
		require.Equal(t, setup.CodeAnswersInvalid, removeCode(t, err), "%q", typed)
	}
	require.True(t, schemaExists(t, d, "basalt_meta"))
	require.Positive(t, prefixRoles(t, d))

	done, err := setup.RunRemove(ctx, d.Admin, database)
	require.NoError(t, err)
	require.Equal(t, database, done.Database)
	require.Equal(t, []string{"ops_bot", "sales_bot"}, done.Bots)
	require.Empty(t, done.Warnings)
	require.False(t, schemaExists(t, d, "basalt_meta"))
	require.False(t, schemaExists(t, d, "basalt_demo"))
	require.Zero(t, prefixRoles(t, d), "every role of the prefix is dropped")
}

// What is left after the guard's schema went (a removal that stopped half
// way) is its roles; with neither, there is nothing to remove.
func TestRemovePlanWithoutAGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.NewAgent(t, "sales_bot", nil, nil)
	ctx := context.Background()
	d.Exec(t, `DROP SCHEMA basalt_meta CASCADE`)

	tx, err := d.Admin.Begin(ctx)
	require.NoError(t, err)
	p, err := setuprun.PlanRemove(ctx, setupstore.New(), tx, d.Names.Prefix)
	require.NoError(t, err)
	require.False(t, p.Installed)
	require.Equal(t, []string{"sales_bot"}, p.Agents)
	require.False(t, p.Nothing())
	require.Contains(t, p.Lines()[0], "no longer in the database")
	require.NoError(t, tx.Rollback(ctx))

	var database string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	tx, err = d.Admin.Begin(ctx)
	require.NoError(t, err)
	_, _, err = setuprun.RunRemove(ctx, setupstore.New(), tx, d.Names.Prefix, database)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Zero(t, prefixRoles(t, d))

	tx, err = d.Admin.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	p, err = setuprun.PlanRemove(ctx, setupstore.New(), tx, d.Names.Prefix)
	require.NoError(t, err)
	require.True(t, p.Nothing())
	require.Contains(t, p.Lines()[0], "nothing to drop")
}

// A guard installed with another prefix is not this removal's.
func TestRemovePlanRefusesAnotherPrefix(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.NewAgent(t, "sales_bot", nil, nil)
	ctx := context.Background()
	tx, err := d.Admin.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = setuprun.PlanRemove(ctx, setupstore.New(), tx, d.Names.Prefix+"x")
	var r *setuprun.RefusalError
	require.ErrorAs(t, err, &r)
	require.Equal(t, "PREFIX_MISMATCH", r.Code)
}

// A basalt_meta owned by a role that is not a guard role is not BasaltDB's:
// its owner's name never picks the roles a removal drops.
func TestRemoveRefusesABasaltMetaNotOwnedByAGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx := context.Background()
	app := d.Names.Prefix + "app"
	d.Exec(t, "CREATE ROLE "+app+" NOLOGIN")
	d.Exec(t, "CREATE ROLE "+app+"_guard NOLOGIN")
	d.Exec(t, "CREATE ROLE "+app+"_agents NOLOGIN")
	t.Cleanup(func() {
		for _, r := range []string{app + "_agents", app + "_guard", app} {
			_, _ = d.Admin.Exec(context.Background(), "DROP OWNED BY "+r)
			_, _ = d.Admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	})
	d.Exec(t, "CREATE SCHEMA basalt_meta AUTHORIZATION "+app)
	var database string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database))

	_, err := setup.CheckRemove(ctx, d.Admin)
	require.Equal(t, "PREFIX_MISMATCH", removeCode(t, err))
	_, err = setup.RunRemove(ctx, d.Admin, database+"x")
	require.Equal(t, setup.CodeAnswersInvalid, removeCode(t, err), "the typed name is checked before the guard's owner")
	_, err = setup.RunRemove(ctx, d.Admin, database)
	require.Equal(t, "PREFIX_MISMATCH", removeCode(t, err))
	require.True(t, schemaExists(t, d, "basalt_meta"), "nothing dropped")
	var roles int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(*)::int FROM pg_catalog.pg_roles WHERE starts_with(rolname, $1)`, app).Scan(&roles))
	require.Equal(t, 3, roles, "no role of the owner's name is dropped")
}
