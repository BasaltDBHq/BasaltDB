package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func TestEveryMigrationIsListedBreakingByDefault(t *testing.T) {
	t.Parallel()
	migs := guard.Migrations()
	require.Len(t, migs, guard.LatestVersion())
	for i, m := range migs {
		require.Equal(t, i+1, m.Version)
	}
}

func TestAgentStatus(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	latest := guard.LatestVersion()
	migs := guard.Migrations()

	st, err := guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guard.Status{State: guard.GuardOK, Installed: latest, Build: latest}, st)
	require.True(t, st.Served())

	// A breaking version in the middle not recorded: missing, though newer
	// ones are.
	gap := 0
	for _, m := range migs[:len(migs)-1] {
		if m.Breaking {
			gap = m.Version
		}
	}
	require.NotZero(t, gap)
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version = $1`, gap)
	st, err = guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guard.GuardOutdated, st.State)
	require.Equal(t, []int{gap}, st.MissingBreaking)
	require.Equal(t, latest, st.Installed)
	require.False(t, st.Served())

	// The same gap in a non-breaking migration only: served.
	nonBreaking := append([]guard.Migration(nil), migs...)
	nonBreaking[gap-1].Breaking = false
	st, err = guard.AgentStatus(ctx, a.Conn, nonBreaking)
	require.NoError(t, err)
	require.Equal(t, guard.GuardUpgradeAvailable, st.State)
	require.Equal(t, []int{gap}, st.MissingNonBreaking)
	require.Empty(t, st.MissingBreaking)
	require.True(t, st.Served())

	// A guard newer than the build.
	d.Exec(t, `INSERT INTO basalt_meta.schema_version (version) VALUES ($1), ($2)`, gap, latest+1)
	st, err = guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guard.GuardNewer, st.State)
	require.True(t, st.Served())

	// A guard from before agents could read schema_version: every later
	// version is missing.
	d.Exec(t, `REVOKE SELECT ON basalt_meta.schema_version FROM `+d.Names.Agents())
	st, err = guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guard.GuardOutdated, st.State)
	const agentsReadVersion = 13 // versionAgentVersion: agents read schema_version from here on
	for _, m := range migs[agentsReadVersion-1:] {
		missing := st.MissingNonBreaking
		if m.Breaking {
			missing = st.MissingBreaking
		}
		require.Contains(t, missing, m.Version)
	}
	require.NotContains(t, st.MissingBreaking, 1)
}

func TestAgentStatusNoGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	st, err := guard.AgentStatus(context.Background(), d.Admin, guard.Migrations())
	require.NoError(t, err)
	require.Equal(t, guard.GuardMissing, st.State)
	require.Zero(t, st.Installed)
	require.False(t, st.Served())
}

func TestLatestAgentSetupWithoutSetups(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	_, ok, err := guard.LatestAgentSetup(context.Background(), a.Conn)
	require.NoError(t, err)
	require.False(t, ok)
}
