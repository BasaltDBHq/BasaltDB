package localsetup_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setuppage"
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

// A SETUP_FAILED carries its cause to the engine's log: the step, the
// SQLSTATE and the server's message, never the admin's password or a
// connection string, even when the database's error holds them. The
// person sees the SQLSTATE and the step.
func TestSetupFailedLogsItsCauseWithoutSecrets(t *testing.T) {
	t.Parallel()
	f := reset(t)
	// An admin of its own, with a password no other text holds.
	const adminPW = "Zq9-distinct-admin-pw"
	admin := f.db.Names.Prefix + "_zadmin"
	f.db.Exec(t, `CREATE ROLE `+admin+` LOGIN SUPERUSER PASSWORD '`+adminPW+`'`)
	t.Cleanup(func() {
		_, _ = f.db.Admin.Exec(context.Background(), `DROP OWNED BY `+admin+`; DROP ROLE `+admin)
	})
	u, err := url.Parse(f.db.URL)
	require.NoError(t, err)
	u.User = url.UserPassword(admin, adminPW)
	adminURL := u.String()
	const otherPW = "Xk7-another-secret"
	// attach_all is the install script's last statement: make it fail with
	// the admin's password, a connection string and a password parameter
	// in its message.
	f.db.Exec(t, `CREATE OR REPLACE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'attach failed: % / % / password=`+otherPW+`', '`+adminPW+`', 'postgres://x' || ':`+otherPW+`@db.example/app'; END $$`)

	var logs bytes.Buffer
	h := setuppage.SetupOnlyHandler(origin, f.svc, slog.New(slog.NewTextHandler(&logs, nil)))
	req := f.request()
	req.DatabaseURL = adminURL
	var checked localsetup.CheckAnswer
	require.Equal(t, http.StatusOK, post(t, h, pageserver.SetupCheckPath, req, &checked))
	req.Challenge = checked.Challenge
	if checked.PasskeyNeeded {
		req.Passkey = register(t, *checked.Challenge)
	}
	var refused struct{ Code, Message string }
	require.Equal(t, http.StatusConflict, post(t, h, pageserver.SetupRunPath, req, &refused))
	require.Equal(t, localsetup.CodeSetupFailed, refused.Code)
	require.Contains(t, refused.Message, "Postgres error P0001, install script, statement")
	require.NotContains(t, refused.Message, "attach failed", "the cause stays in the log")

	line := logs.String()
	require.Contains(t, line, "code=SETUP_FAILED")
	require.Contains(t, line, "sqlstate=P0001")
	require.Contains(t, line, `step="install script, statement`)
	require.Contains(t, line, "attach failed")
	for _, secret := range []string{adminPW, otherPW, "postgres://"} {
		require.NotContains(t, line, secret)
		require.NotContains(t, refused.Message, secret)
	}
	require.NoFileExists(t, f.config)
}

// The Update check refuses an older install the same way, and never says
// the guard is newer than this engine.
func TestAnUpdateRefusesAnOlderInstallItCannotUse(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	f.db.Exec(t, `SET ROLE `+f.db.Names.Guard()+`; DROP TABLE basalt_meta.installs CASCADE;
		INSERT INTO basalt_meta.schema_version (version) VALUES (30); RESET ROLE`)
	before := guardObjects(t, f)
	_, err := svc.Check(ctx, f.agentJob(localsetup.JobUpdate))
	refusal(t, err, localsetup.CodeGuardUnusable)
	_, err = svc.Run(ctx, f.agentJob(localsetup.JobUpdate))
	refusal(t, err, localsetup.CodeGuardUnusable)
	require.Equal(t, before, guardObjects(t, f), "nothing changed in basalt_meta")
}
