package setup_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// A database with an older BasaltDB install this build cannot use (here
// one from before the guard's versions started again at 1: no installs
// table, a version this build does not have) is refused at Check, before
// the person approves anything, and Run changes nothing.
func TestCheckRefusesAnOlderInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{Name: "other", Password: guard.NewPassword(), Write: []string{"public.leads"}})
	d.Exec(t, `SET ROLE `+d.Names.Guard()+`;
		DROP TABLE basalt_meta.installs CASCADE;
		INSERT INTO basalt_meta.schema_version (version) VALUES (30);
		RESET ROLE`)
	code := newCode(t, d, nil)

	_, err := setup.Check(ctx, d.Admin, request(code))
	require.Equal(t, setup.CodeGuardUnusable, codeOf(t, err))
	require.Contains(t, err.Error(), "older BasaltDB install")
	require.Contains(t, err.Error(), "docs/remove-old-install.md")
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Equal(t, setup.CodeGuardUnusable, codeOf(t, err))
	var versions int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(*) FROM basalt_meta.schema_version WHERE version = 30`).Scan(&versions))
	require.Equal(t, 1, versions, "nothing changed")
}

// A guard recorded at version 1, as every 0.0.1 release left it, is below
// the update floor: Check and Run refuse it GUARD_UNUSABLE and change
// nothing.
func TestCheckRefusesAnInstallFrom001(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{Name: "other", Password: guard.NewPassword(), Write: []string{"public.leads"}})
	d.Exec(t, `SET ROLE `+d.Names.Guard()+`;
		DELETE FROM basalt_meta.schema_version WHERE version > 1;
		RESET ROLE`)
	code := newCode(t, d, nil)

	_, err := setup.Check(ctx, d.Admin, request(code))
	require.Equal(t, setup.CodeGuardUnusable, codeOf(t, err))
	require.Contains(t, err.Error(), "docs/remove-old-install.md")
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Equal(t, setup.CodeGuardUnusable, codeOf(t, err))
	require.Equal(t, []int32{1}, versionsOf(t, d), "nothing changed")
}

// from001 is a database whose guard is at version 1, as every 0.0.1
// release left it, with the agent bot of that install: below the update
// floor. Its schema_version has 0.0.1's shape: no release column.
func from001(t *testing.T) *guardtest.DB {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Password: guard.NewPassword(), Write: []string{"public.leads"}})
	d.Exec(t, `SET ROLE `+d.Names.Guard()+`;
		DELETE FROM basalt_meta.schema_version WHERE version > 1;
		ALTER TABLE basalt_meta.schema_version DROP COLUMN release;
		RESET ROLE`)
	return d
}

func versionsOf(t *testing.T, d *guardtest.DB) []int32 {
	t.Helper()
	var versions []int32
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT array_agg(version ORDER BY version) FROM basalt_meta.schema_version`).Scan(&versions))
	return versions
}

// A caller that offers the replace (Request.Replace) gets an INSTALL code
// on a guard below the update floor checked as after the old install's
// removal, with what the first screen says; Run removes it and installs in
// one transaction once the database's name is typed, and nothing changes
// before.
func TestAnInstallCodeReplacesAnInstallFrom001(t *testing.T) {
	t.Parallel()
	d := from001(t)
	ctx := context.Background()
	req := request(newCode(t, d, nil))
	req.Replace = true

	checked, err := setup.Check(ctx, d.Admin, req)
	require.NoError(t, err, "the old agent role bot is no ROLE_EXISTS: it goes with the old install")
	require.NotNil(t, checked.Replace)
	require.Equal(t, 1, checked.Replace.GuardVersion)
	require.Equal(t, 2, checked.Replace.Floor)
	require.Empty(t, checked.Replace.Release)
	require.Equal(t, "It has guard version 1.", checked.Replace.Lines[1])
	require.True(t, checked.PasskeyNeeded)
	require.Equal(t, []int32{1}, versionsOf(t, d), "Check changed nothing")

	_, give := personPasskey(t)
	var database string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT pg_catalog.current_database()::text`).Scan(&database))
	for _, typed := range []string{"", database + "x"} {
		_, err = setup.Run(ctx, d.Admin, req, setup.RunInput{Passkey: verified(t, give), ConfirmName: typed})
		require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err), "%q", typed)
		require.Equal(t, []int32{1}, versionsOf(t, d), "nothing changed")
	}

	var shown string
	res, err := setup.Run(ctx, d.Admin, req, setup.RunInput{
		Passkey: verified(t, give), ConfirmName: database,
		Approve: func(p setup.Plan) error { shown = p.SQL; return nil },
	})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.Contains(t, shown, "DROP SCHEMA IF EXISTS basalt_meta CASCADE;\n", "the removal comes first in the SQL shown")
	versions := versionsOf(t, d)
	require.Equal(t, int32(guard.LatestVersion()), versions[len(versions)-1])
}

// A guard at the floor is never replaced: Check has no Replace, and a
// typed name is refused.
func TestAnInstallCodeReplacesNothingAtTheFloor(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{Name: "other", Password: guard.NewPassword(), Write: []string{"public.leads"}})
	req := request(newCode(t, d, nil))
	req.Replace = true
	checked, err := setup.Check(ctx, d.Admin, req)
	require.NoError(t, err)
	require.Nil(t, checked.Replace)
	_, give := personPasskey(t)
	_, err = setup.Run(ctx, d.Admin, req, setup.RunInput{Passkey: verified(t, give), ConfirmName: "anything"})
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err))
}
