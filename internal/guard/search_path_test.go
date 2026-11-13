package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// shadowCatalog makes the agent's session hold temporary tables named
// after every catalog relation the guard's functions read, readable by
// everyone (so a SECURITY DEFINER function could read them), with
// pg_roles saying every role is a superuser and the rest empty. Postgres
// searches pg_temp before pg_catalog for relations unless search_path
// names pg_temp, so a function with search_path = pg_catalog alone and an
// unqualified pg_roles would read the lie and let the write through.
const shadowCatalog = `
DO $$
DECLARE
    r    text;
    cols text;
BEGIN
    FOREACH r IN ARRAY ARRAY['pg_roles', 'pg_auth_members', 'pg_class', 'pg_namespace', 'pg_attribute',
                             'pg_index', 'pg_constraint', 'pg_policy', 'pg_trigger'] LOOP
        -- Every column but pseudo-typed ones (pg_attribute.attmissingval),
        -- which a table cannot have.
        SELECT pg_catalog.string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO cols
          FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = pg_catalog.to_regclass('pg_catalog.' || r) AND a.attnum > 0 AND NOT a.attisdropped
           AND a.atttypid <> 'pg_catalog.anyarray'::pg_catalog.regtype;
        EXECUTE pg_catalog.format('CREATE TEMP TABLE %I AS SELECT %s FROM pg_catalog.%I', r, cols, r);
        EXECUTE pg_catalog.format('GRANT SELECT ON pg_temp.%I TO PUBLIC', r);
        IF r <> 'pg_roles' THEN
            EXECUTE pg_catalog.format('DELETE FROM pg_temp.%I', r);
        END IF;
    END LOOP;
    UPDATE pg_temp.pg_roles SET rolsuper = true, rolbypassrls = true;
END $$`

// An agent role that shadows the catalog with temporary tables in its own
// session still cannot write without an intent, past the row limits or
// unrecorded: the guard's functions read pg_catalog only.
func TestCatalogShadowDoesNotBypassGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.scratch (id int PRIMARY KEY)`)
	a := d.NewAgent(t, "bot", []string{"public.leads", "public.scratch"}, leads)
	d.Exec(t, `GRANT TRUNCATE ON public.scratch TO `+a.Role)
	ctx := context.Background()
	in := newRun(t, a, "Tidy lead statuses")

	_, err := a.Conn.Exec(ctx, shadowCatalog)
	require.NoError(t, err)
	var shadowed bool
	// The session does resolve the unqualified name to its own table.
	require.NoError(t, a.Conn.QueryRow(ctx,
		`SELECT rolsuper FROM pg_roles WHERE rolname = session_user`).Scan(&shadowed))
	require.True(t, shadowed)

	_, err = a.Conn.Exec(ctx, `UPDATE public.leads SET status = 'lost' WHERE id = 4`)
	requireCode(t, err, guard.CodeIntentRequired)

	err = guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'lost' WHERE id <= 25`)
	requireCode(t, err, guard.CodeApprovalRequired)

	err = guardtest.Guarded(ctx, a.Conn, in, `DELETE FROM public.leads WHERE id = 5`)
	requireCode(t, err, guard.CodeApprovalRequired)

	_, err = a.Conn.Exec(ctx, `TRUNCATE public.scratch`)
	requireCode(t, err, guard.CodeNotAllowed)

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'lost' WHERE id = 4`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'ROW_CHANGE' AND agent = $1 AND row_key = '{"id": 4}'::jsonb`, a.Role))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(id)::int FROM public.leads WHERE status = 'lost'`))
}

// Every function in basalt_meta runs with search_path = pg_catalog,
// pg_temp: pg_temp named last, so the caller's temporary tables and types
// never shadow a catalog name. Not only SECURITY DEFINER and trigger
// functions: a helper they call runs with their privileges too.
func TestEveryGuardFunctionPutsPgTempLast(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()

	// Plain SQL: a catalog query.
	rows, err := d.Admin.Query(ctx, `SELECT p.oid::regprocedure::text, coalesce(p.proconfig, '{}')
		FROM pg_proc p WHERE p.pronamespace = 'basalt_meta'::regnamespace ORDER BY 1`)
	require.NoError(t, err)
	type fn struct {
		Name   string
		Config []string
	}
	fns, err := pgx.CollectRows(rows, pgx.RowToStructByPos[fn])
	require.NoError(t, err)
	require.NotEmpty(t, fns)
	var secdef int
	// Plain SQL: a catalog count.
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(oid)::int FROM pg_proc
		WHERE pronamespace = 'basalt_meta'::regnamespace AND (prosecdef OR prorettype = 'trigger'::regtype)`).Scan(&secdef))
	require.Positive(t, secdef)
	for _, f := range fns {
		require.Contains(t, f.Config, "search_path=pg_catalog, pg_temp", f.Name)
	}
}

// No function in basalt_meta names a catalog relation without
// pg_catalog., so it never depends on search_path to find it.
func TestGuardFunctionsQualifyCatalogRelations(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)

	// Plain SQL: a catalog query with a regular expression per relation.
	rows, err := d.Admin.Query(context.Background(), `
		SELECT p.oid::regprocedure::text || ': ' || c.relname
		  FROM pg_proc p
		  JOIN pg_class c ON c.relnamespace = 'pg_catalog'::regnamespace
		 WHERE p.pronamespace = 'basalt_meta'::regnamespace
		   AND p.prosrc ~ ('(?<!pg_catalog\.)\m' || c.relname || '\M')
		 ORDER BY 1`)
	require.NoError(t, err)
	unqualified, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Empty(t, unqualified)
}
