package guard_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// The stale-version check and the upgrade that clears it, with a test-only
// version 2 after this build's own.
func TestCheckAgentVersion(t *testing.T) {
	d := guardtest.New(t).WithDemo(t)
	latest := guardtest.NextVersion(t, false)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()

	// The agent reads the version init installed: current.
	require.NoError(t, guard.CheckAgentVersion(ctx, a.Conn))

	// An older guard (the newest version's row gone): refused, naming both.
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version = $1`, latest)
	err := guard.CheckAgentVersion(ctx, a.Conn)
	var stale *guard.StaleSchemaError
	require.ErrorAs(t, err, &stale)
	require.Equal(t, latest-1, stale.Installed)
	require.EqualError(t, err, fmt.Sprintf(
		"guard schema v%d is older than this build's v%d: run basalt init again to upgrade it (same flags as before)", latest-1, latest))

	// Running init again upgrades it, running only the missing version.
	d.Init(t, guard.AgentSpec{Name: "bot", Password: a.Password, Write: leads, Read: leads})
	require.NoError(t, guard.CheckAgentVersion(ctx, a.Conn))

	// An agent that cannot read schema_version, which every version grants
	// it: refused as unreadable.
	d.Exec(t, `REVOKE SELECT ON basalt_meta.schema_version FROM `+d.Names.Agents())
	err = guard.CheckAgentVersion(ctx, a.Conn)
	require.ErrorAs(t, err, &stale)
	require.True(t, stale.Unreadable)
	require.Zero(t, stale.Installed)
	require.EqualError(t, err, fmt.Sprintf(
		"this agent cannot read the guard schema version (this build's is v%d): run basalt init again to upgrade it (same flags as before)", latest))
}

// basalt init plans only the versions a guard lacks, up to a setup code's
// guard.to when one is given, and records each in schema_version.
func TestPlanInitAppliesOnlyMissingVersions(t *testing.T) {
	d := guardtest.New(t).WithDemo(t)
	next := guardtest.NextVersion(t, false)
	ctx := context.Background()
	apply := func(upTo int) guard.Script {
		s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, UpTo: upTo})
		require.NoError(t, err)
		require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return s.Apply(ctx, tx) }))
		return s
	}
	versions := func() []int {
		rows, err := d.Admin.Query(ctx, `SELECT version FROM basalt_meta.schema_version ORDER BY version`)
		require.NoError(t, err)
		out, err := pgx.CollectRows(rows, pgx.RowTo[int])
		require.NoError(t, err)
		return out
	}
	probe := fmt.Sprintf("basalt_meta.upgrade_probe_v%d", next)

	first := apply(next - 1).SQL()
	require.Equal(t, versionsUpTo(next-1), versions())
	require.Contains(t, first, "CREATE TABLE basalt_meta.guarded_tables")
	require.NotContains(t, first, probe)

	second := apply(0).SQL()
	require.Equal(t, versionsUpTo(next), versions())
	require.Contains(t, second, probe)
	require.Contains(t, second, fmt.Sprintf("INSERT INTO basalt_meta.schema_version (version) VALUES (%d);", next))
	require.NotContains(t, second, "CREATE TABLE basalt_meta.guarded_tables", "version 1 does not run again")

	third := apply(0).SQL()
	require.NotContains(t, third, "INSERT INTO basalt_meta.schema_version", "nothing is missing")
}

// An engine serves a guard newer than its build: a setup code's guard.to
// may be newer than the engine that made it, once the person's computer
// ran a newer basalt (CONTRACT.md, Setup from your laptop).
func TestCheckAgentVersionServesNewerGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	d.Exec(t, `INSERT INTO basalt_meta.schema_version (version) VALUES ($1)`, guard.LatestVersion()+1)
	require.NoError(t, guard.CheckAgentVersion(context.Background(), a.Conn))
}

func TestCheckAgentVersionNoGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	err := guard.CheckAgentVersion(context.Background(), d.Admin)
	var stale *guard.StaleSchemaError
	require.ErrorAs(t, err, &stale)
	require.Zero(t, stale.Installed)
}

// versionsUpTo is every version from 1 to n, in order.
func versionsUpTo(n int) []int {
	out := make([]int, 0, n)
	for v := 1; v <= n; v++ {
		out = append(out, v)
	}
	return out
}
