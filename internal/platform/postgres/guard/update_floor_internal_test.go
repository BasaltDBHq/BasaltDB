package guard

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The update floor: every 0.0.1 release shipped only version 1, so a guard
// recorded below the floor is refused as unusable whatever else it holds,
// and one at the floor or above is updated as before.
func TestUsableRefusesAGuardBelowTheUpdateFloor(t *testing.T) {
	t.Parallel()
	require.Equal(t, 2, updatableFrom(), "0.0.1 shipped version 1 only; raising the floor is a breaking change for alpha installs")

	for _, shape := range []struct{ installs, installID bool }{{true, false}, {true, true}, {false, false}} {
		err := usable(versionGuard, true, shape.installs, shape.installID)
		require.ErrorIs(t, err, ErrUnusableInstall, "%+v", shape)
		require.EqualError(t, err, ErrUnusableInstall.Error()+": version 1 is older than this build can update")
	}

	require.NoError(t, usable(updatableFrom(), true, true, true), "the floor itself is updated")
	require.NoError(t, usable(LatestVersion(), true, true, true))
	require.NoError(t, usable(0, false, false, false), "an empty basalt_meta")
	require.ErrorIs(t, usable(0, true, true, true), ErrUnusableInstall, "objects but no version")
	require.ErrorIs(t, usable(updatableFrom(), true, true, false), ErrUnusableInstall, "an installs table of an older shape")
}

// The update floor is the highest version marked reinstall, 1 when none
// is; this build marks version 2 only.
func TestTheUpdateFloorIsTheHighestReinstallVersion(t *testing.T) {
	t.Parallel()
	ms := func(reinstall ...int) []migration {
		out := make([]migration, 0, 6)
		for v := 1; v <= 6; v++ {
			out = append(out, migration{version: v, reinstall: slices.Contains(reinstall, v)})
		}
		return out
	}
	require.Equal(t, 1, floorOf(ms()))
	require.Equal(t, 2, floorOf(ms(2)))
	require.Equal(t, 5, floorOf(ms(2, 5)))

	var marked []int
	for _, m := range migrations {
		if m.reinstall {
			marked = append(marked, m.version)
		}
	}
	require.Equal(t, []int{versionInstallIDs}, marked, "0.0.1's version 1 is other SQL than today's")
	for _, m := range migrations {
		require.False(t, m.reinstall && m.nonBreaking, "version %d: a version no update reaches is never served without", m.version)
	}
}

// judge marks a guard below the floor, and its state is OUTDATED even when
// it misses no breaking version, so the engine never offers the update.
func TestJudgeMarksAGuardBelowTheFloor(t *testing.T) {
	t.Parallel()
	st := StatusAt(versionGuard, Migrations())
	require.True(t, st.BelowFloor)
	require.Equal(t, guardmodel.GuardOutdated, st.State)
	require.Equal(t, versionGuard, st.Installed)
	nonBreaking := []guardmodel.Migration{{Version: 1, Breaking: true}, {Version: 2, Breaking: false}}
	require.Equal(t, guardmodel.GuardOutdated, StatusAt(versionGuard, nonBreaking).State, "never UPGRADE_AVAILABLE below the floor")

	for _, v := range []int{0, updatableFrom(), LatestVersion()} {
		require.False(t, StatusAt(v, Migrations()).BelowFloor, "version %d", v)
	}
}
