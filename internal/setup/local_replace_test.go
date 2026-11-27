package setup_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// from001 is a database whose guard is at version 1, as every 0.0.1
// release left it: below the update floor. The engine on this computer
// forgot it (reset), so the page offers an install.
func from001(t *testing.T) *fixture {
	t.Helper()
	f := reset(t)
	f.db.Exec(t, `SET ROLE `+f.db.Names.Guard()+`; DELETE FROM basalt_meta.schema_version WHERE version > 1; RESET ROLE`)
	return f
}

// databaseName is the database's name, as the person types it.
func databaseName(t *testing.T, f *fixture) string {
	t.Helper()
	var name string
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT pg_catalog.current_database()::text`).Scan(&name))
	return name
}

// agentRoles counts the agent roles of the fixture's prefix.
func agentRoles(t *testing.T, f *fixture) int {
	t.Helper()
	var n int
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT count(1) FROM pg_catalog.pg_roles WHERE starts_with(rolname::text, $1)`,
		f.db.Names.AgentPrefix()).Scan(&n))
	return n
}

// An install on a guard below the update floor replaces it: the check
// says so from data (the version, no release recorded, the floor and this
// build), plans on the database as the run will find it and changes
// nothing; the run removes the old install and installs, in one
// transaction, once the database's name is typed.
func TestAnInstallReplacesAGuardBelowTheFloor(t *testing.T) {
	t.Parallel()
	f := from001(t)
	ctx := context.Background()
	before := guardObjects(t, f)

	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.Equal(t, &setup.Replace{GuardVersion: 1, Floor: 2, This: setup.ThisRelease(), Lines: []string{
		"This BasaltDB install is too old to update.",
		"It has guard version 1.",
		fmt.Sprintf("BasaltDB %s needs guard version 2 or later.", setup.ThisRelease()),
		"Setting up removes the old install first: its agents' history and undo, their held approvals and the passkeys go with it. Your tables and rows stay.",
	}}, checked.Replace)
	require.True(t, checked.PasskeyNeeded, "the old install's passkeys go with it")
	require.Contains(t, checked.SQL, "DROP SCHEMA IF EXISTS basalt_meta CASCADE;\n")
	require.Contains(t, checked.Lines[0], "It first removes the old BasaltDB install")
	require.Equal(t, before, guardObjects(t, f), "the check rolled its removal back")

	req := f.request()
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	for name, typed := range map[string]string{"no name": "", "another name": databaseName(t, f) + "x"} {
		req.ConfirmName = typed
		_, err = f.svc.Run(ctx, req)
		refusal(t, err, setup.CodeAnswersInvalid)
		require.Equal(t, before, guardObjects(t, f), "%s: nothing changed", name)
	}
	require.NoFileExists(t, f.config)

	req.ConfirmName = databaseName(t, f)
	ran, err := f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "the old BasaltDB install (guard version 1) removed from the database "+req.ConfirmName, ran.Lines[0])
	var latest int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT max(version) FROM basalt_meta.schema_version`).Scan(&latest))
	require.Equal(t, guard.LatestVersion(), latest)
	var passkeys int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(1) FROM basalt_meta.passkeys`).Scan(&passkeys))
	require.Equal(t, 1, passkeys, "only the passkey this run registered")
	require.FileExists(t, f.config)
}

// A replace that fails during the install leaves the old install as it
// was: the removal and the install are one transaction.
func TestAReplaceThatFailsLeavesTheOldInstall(t *testing.T) {
	t.Parallel()
	f := from001(t)
	ctx := context.Background()
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.NotNil(t, checked.Replace)
	before, roles := guardObjects(t, f), agentRoles(t, f)
	// The install's first new function fails, after the old install is
	// dropped in the run's transaction.
	f.db.Exec(t, `CREATE FUNCTION public.refuse_install() RETURNS event_trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'no new function here'; END $$;
		CREATE EVENT TRIGGER refuse_install ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION public.refuse_install()`)
	t.Cleanup(func() { _, _ = f.db.Admin.Exec(context.Background(), `DROP EVENT TRIGGER IF EXISTS refuse_install`) })

	req := f.request()
	req.Challenge, req.Passkey, req.ConfirmName = checked.Challenge, register(t, *checked.Challenge), databaseName(t, f)
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, setup.CodeSetupFailed)
	require.Equal(t, before, guardObjects(t, f), "the old install is untouched")
	require.Equal(t, roles, agentRoles(t, f), "its roles too")
	require.NoFileExists(t, f.config)
}

// A guard at or above the floor is never replaced: the install has no
// replace, and a typed name on it is refused.
func TestAnInstallReplacesNothingAtTheFloor(t *testing.T) {
	t.Parallel()
	f := reset(t)
	ctx := context.Background()
	checked, err := f.svc.Check(ctx, f.request())
	require.NoError(t, err)
	require.Nil(t, checked.Replace)
	require.NotContains(t, checked.SQL, "DROP SCHEMA")
	req := f.request()
	req.Challenge, req.ConfirmName = checked.Challenge, databaseName(t, f)
	if checked.PasskeyNeeded {
		req.Passkey = register(t, *checked.Challenge)
	}
	_, err = f.svc.Run(ctx, req)
	refusal(t, err, setup.CodeAnswersInvalid)
}

// The first screen names the release recorded with the old guard when it
// has one: here a later breaking release raises the floor above the guard
// this build installed.
func TestAReplaceNamesTheRecordedRelease(t *testing.T) {
	f := reset(t)
	floor := guard.LatestVersion() + 1
	guardtest.WithMigrations(t, guard.TestMigration{Version: floor, SQL: "\nSELECT 1;\n", Reinstall: true})
	checked, err := f.svc.Check(context.Background(), f.request())
	require.NoError(t, err)
	require.NotNil(t, checked.Replace)
	require.Equal(t, setup.ThisRelease(), checked.Replace.Release)
	require.Equal(t, fmt.Sprintf("It was set up by BasaltDB %s (guard version %d).", setup.ThisRelease(), floor-1), checked.Replace.Lines[1])
	require.Equal(t, fmt.Sprintf("BasaltDB %s needs guard version %d or later.", setup.ThisRelease(), floor), checked.Replace.Lines[2])
}
