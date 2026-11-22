package localsetup_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/localsetup"
)

// reset is an install whose engine config and credential are gone, as on
// a computer that forgot its setup: the database keeps everything.
func reset(t *testing.T) *fixture {
	t.Helper()
	f, _ := installed(t)
	require.NoError(t, os.Remove(f.config))
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")))
	return f
}

// guardObjects is every object in basalt_meta with the versions recorded,
// so a test can see that nothing changed.
func guardObjects(t *testing.T, f *fixture) []string {
	t.Helper()
	ctx := context.Background()
	rows, err := f.db.Admin.Query(ctx, `
		SELECT 'rel ' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'basalt_meta'
		UNION ALL
		SELECT 'fn ' || p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'basalt_meta'
		ORDER BY 1`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	var versioned bool
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT to_regclass('basalt_meta.schema_version') IS NOT NULL`).Scan(&versioned))
	if versioned {
		rows, err := f.db.Admin.Query(ctx, `SELECT 'version ' || version FROM basalt_meta.schema_version ORDER BY version`)
		require.NoError(t, err)
		versions, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		out = append(out, versions...)
	}
	return out
}

// An older install this build cannot use (one from before the guard's
// versions were renumbered, whose basalt_meta has no installs table or an
// installs table of another shape, or a partial one) is refused at check,
// before the person signs anything, with the way to remove it. Before,
// check passed and run failed SETUP_FAILED on 42P01 (relation
// "basalt_meta.installs" does not exist).
func TestAnInstallRefusesAnOlderInstallItCannotUse(t *testing.T) {
	t.Parallel()
	for name, old := range map[string]string{
		"older numbering, no installs table": `DROP TABLE basalt_meta.installs CASCADE;
			INSERT INTO basalt_meta.schema_version (version) VALUES (30)`,
		"older numbering, installs keyed by the schema oid": `DROP TABLE basalt_meta.installs CASCADE;
			CREATE TABLE basalt_meta.installs (install oid PRIMARY KEY, installed_at timestamptz NOT NULL, installed_by name NOT NULL, vault_user text);
			INSERT INTO basalt_meta.schema_version (version) VALUES (37)`,
		"no version table": `DROP TABLE basalt_meta.schema_version CASCADE`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := reset(t)
			ctx := context.Background()
			f.db.Exec(t, `SET ROLE `+f.db.Names.Guard()+`; `+old+`; RESET ROLE`)
			before := guardObjects(t, f)

			_, err := f.svc.Check(ctx, f.request())
			refusal(t, err, localsetup.CodeGuardUnusable)
			var r *localsetup.RefusalError
			require.ErrorAs(t, err, &r)
			require.Contains(t, r.Message, "older BasaltDB install")
			require.Contains(t, r.Message, "docs/remove-old-install.md")
			require.Contains(t, r.Message, "Nothing changed.")

			// A run without the check is refused the same way.
			_, err = f.svc.Run(ctx, f.request())
			refusal(t, err, localsetup.CodeGuardUnusable)
			require.Equal(t, before, guardObjects(t, f), "nothing changed in basalt_meta")
			require.NoFileExists(t, f.config)
		})
	}
}

// A SETUP_FAILED carries its cause for the engine's log: the step, the
// SQLSTATE and the server's message, never the admin's password or a
// connection string. The person sees the SQLSTATE and the step.
func TestSetupFailedCarriesItsCauseWithoutSecrets(t *testing.T) {
	t.Parallel()
	f := reset(t)
	ctx := context.Background()
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	adminPW, _ := u.User.Password()
	leak := "postgres://someone:" + adminPW + "@db.example:5432/app"
	// attach_all is the install script's last statement: make it fail with
	// the admin's password and a connection string in its message.
	f.db.Exec(t, `CREATE OR REPLACE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'attach failed for % with password=%', '`+leak+`', '`+adminPW+`'; END $$`)

	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	req := f.request()
	req.Challenge = checked.Challenge
	if checked.PasskeyNeeded {
		req.Passkey = register(t, *checked.Challenge)
	}
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, localsetup.CodeSetupFailed)
	var r *localsetup.RefusalError
	require.ErrorAs(t, err, &r)
	require.NotNil(t, r.Cause, "a SETUP_FAILED names its cause")
	require.Equal(t, "P0001", r.Cause.SQLState)
	require.Equal(t, "install script, statement", r.Cause.Step[:len("install script, statement")])
	require.Contains(t, r.Cause.Message, "attach failed for")
	for _, s := range []string{r.Cause.Message, r.Cause.Step, r.Message} {
		require.NotContains(t, s, adminPW)
		require.NotContains(t, s, "postgres://someone")
	}
	require.True(t, strings.Contains(r.Message, "P0001"), r.Message)
	require.NoFileExists(t, f.config)
}
