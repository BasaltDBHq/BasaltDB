package guard_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func TestCheckAgentVersion(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	latest := guard.LatestVersion()

	// The agent reads the version init installed: current.
	require.NoError(t, guard.CheckAgentVersion(ctx, a.Conn))

	// An older guard (the rows of later versions gone): refused, naming both.
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version > $1`, latest-1)
	err := guard.CheckAgentVersion(ctx, a.Conn)
	var stale *guard.StaleSchemaError
	require.ErrorAs(t, err, &stale)
	require.Equal(t, latest-1, stale.Installed)
	require.EqualError(t, err, fmt.Sprintf(
		"guard schema v%d is older than this build's v%d: run basalt init again to upgrade it (same flags as before)", latest-1, latest))

	// A guard from before agents could read schema_version.
	d.Exec(t, `REVOKE SELECT ON basalt_meta.schema_version FROM `+d.Names.Agents())
	err = guard.CheckAgentVersion(ctx, a.Conn)
	require.ErrorAs(t, err, &stale)
	require.True(t, stale.Unreadable)
	require.Contains(t, err.Error(), "or earlier is older than this build's")

	// Running init again upgrades it.
	d.Init(t, guard.AgentSpec{Name: "bot", Password: a.Password, Write: leads, Read: leads})
	require.NoError(t, guard.CheckAgentVersion(ctx, a.Conn))
}

func TestCheckAgentVersionNoGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	err := guard.CheckAgentVersion(context.Background(), d.Admin)
	var stale *guard.StaleSchemaError
	require.ErrorAs(t, err, &stale)
	require.Zero(t, stale.Installed)
}
