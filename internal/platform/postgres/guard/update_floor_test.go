package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// basaltMetaObjects lists what basalt_meta holds: its relations, functions
// and recorded versions.
func basaltMetaObjects(t *testing.T, q guard.Querier) []string {
	t.Helper()
	rows, err := q.Query(context.Background(), `
		SELECT 'rel ' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'basalt_meta'
		UNION ALL
		SELECT 'fn ' || p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'basalt_meta'
		UNION ALL
		SELECT 'version ' || version FROM basalt_meta.schema_version
		ORDER BY 1`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// A guard installed at version 1, as every 0.0.1 release left it, is below
// the update floor: CheckUsable refuses it as unusable and basalt init
// plans nothing, so nothing in basalt_meta changes; the agent's status
// says it is below the floor.
func TestAGuardAtVersion1IsNotUpdated(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 1)
	d := guardtest.New(t).WithDemo(t)
	bot := d.NewAgent(t, "bot", leads, nil)
	restore()
	before := basaltMetaObjects(t, d.Admin)

	err := guard.CheckUsable(ctx, d.Admin)
	require.ErrorIs(t, err, guard.ErrUnusableInstall)
	require.ErrorContains(t, err, "version 1 is older than this build can update")
	_, err = guard.PlanInit(ctx, d.Admin, guardmodel.InitOptions{Names: d.Names})
	require.ErrorIs(t, err, guard.ErrUnusableInstall)
	require.Equal(t, before, basaltMetaObjects(t, d.Admin), "nothing changed in basalt_meta")

	st, err := guard.AgentStatus(ctx, bot.Conn, guard.Migrations())
	require.NoError(t, err)
	require.Equal(t, guardmodel.GuardOutdated, st.State)
	require.True(t, st.BelowFloor, "the engine tells the person to remove it, never to update it")
}

// A guard at the update floor, version 2, still updates to this build's.
func TestAGuardAtTheUpdateFloorStillUpdates(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 2)
	d := guardtest.New(t).WithDemo(t)
	bot := d.NewAgent(t, "bot", leads, nil)
	restore()
	require.NoError(t, guard.CheckUsable(ctx, d.Admin))

	st, err := guard.AgentStatus(ctx, bot.Conn, guard.Migrations())
	require.NoError(t, err)
	require.False(t, st.BelowFloor)

	// basalt init over it, as TestPluginApprovalsMigration upgrades.
	d.NewAgent(t, "bot", leads, nil)
	require.Equal(t, guard.LatestVersion(), count(t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
}
