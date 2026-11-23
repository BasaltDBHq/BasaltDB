package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

func TestEveryMigrationIsListedBreakingByDefault(t *testing.T) {
	t.Parallel()
	migs := guard.Migrations()
	require.Len(t, migs, guard.LatestVersion())
	for i, m := range migs {
		require.Equal(t, i+1, m.Version)
	}
	require.True(t, migs[0].Breaking, "version 1 is the whole guard")
}

// AgentStatus judges a real guard against a build's migrations: this
// build's, plus a version 2 the guard does not have, breaking or not.
func TestAgentStatus(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	latest := guard.LatestVersion()
	migs := guard.Migrations()

	st, err := guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guardmodel.Status{State: guardmodel.GuardOK, Installed: latest, Build: latest}, st)
	require.True(t, st.Served())

	// A build with a breaking version the guard lacks: outdated.
	next := latest + 1
	build := append(append([]guardmodel.Migration(nil), migs...), guardmodel.Migration{Version: next, Breaking: true})
	st, err = guard.AgentStatus(ctx, a.Conn, build)
	require.NoError(t, err)
	require.Equal(t, guardmodel.Status{State: guardmodel.GuardOutdated, Installed: latest, Build: next, MissingBreaking: []int{next}}, st)
	require.False(t, st.Served())

	// The same version flagged non-breaking: served, with the upgrade available.
	build[len(build)-1].Breaking = false
	st, err = guard.AgentStatus(ctx, a.Conn, build)
	require.NoError(t, err)
	require.Equal(t, guardmodel.Status{State: guardmodel.GuardUpgradeAvailable, Installed: latest, Build: next, MissingNonBreaking: []int{next}}, st)
	require.True(t, st.Served())

	// A breaking version in the middle not recorded: missing, though a newer
	// one is. Version 1 is breaking.
	d.Exec(t, `INSERT INTO basalt_meta.schema_version (version) VALUES ($1)`, next)
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version = 1`)
	st, err = guard.AgentStatus(ctx, a.Conn, build)
	require.NoError(t, err)
	require.Equal(t, guardmodel.GuardOutdated, st.State)
	require.Equal(t, []int{1}, st.MissingBreaking)
	require.Equal(t, next, st.Installed)
	require.False(t, st.Served())

	// A guard newer than the build.
	d.Exec(t, `INSERT INTO basalt_meta.schema_version (version) VALUES (1)`)
	st, err = guard.AgentStatus(ctx, a.Conn, migs)
	require.NoError(t, err)
	require.Equal(t, guardmodel.GuardNewer, st.State)
	require.True(t, st.Served())

	// An agent that cannot read schema_version, which every version grants
	// it: every version is missing.
	d.Exec(t, `REVOKE SELECT ON basalt_meta.schema_version FROM `+d.Names.Agents())
	st, err = guard.AgentStatus(ctx, a.Conn, build)
	require.NoError(t, err)
	var breaking, nonBreaking []int
	for _, m := range build {
		if m.Breaking {
			breaking = append(breaking, m.Version)
			continue
		}
		nonBreaking = append(nonBreaking, m.Version)
	}
	require.Equal(t, guardmodel.Status{
		State: guardmodel.GuardOutdated, Build: next, MissingBreaking: breaking, MissingNonBreaking: nonBreaking,
	}, st)
}

func TestAgentStatusNoGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	st, err := guard.AgentStatus(context.Background(), d.Admin, guard.Migrations())
	require.NoError(t, err)
	require.Equal(t, guardmodel.GuardMissing, st.State)
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
