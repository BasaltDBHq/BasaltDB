package guard_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// thisRelease is the release this build records.
func thisRelease() string { return strings.TrimPrefix(buildinfo.Version, "v") }

// releases is each schema_version row's version and release ("" for none).
func releases(t *testing.T, q guard.Querier) map[int]string {
	t.Helper()
	rows, err := q.Query(context.Background(), `SELECT version, coalesce(release, '') FROM basalt_meta.schema_version ORDER BY version`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var r string
		require.NoError(t, rows.Scan(&v, &r))
		out[v] = r
	}
	require.NoError(t, rows.Err())
	return out
}

// An install records this build's release on every version it writes.
func TestAnInstallRecordsTheRelease(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	got := releases(t, d.Admin)
	require.Len(t, got, guard.LatestVersion())
	for v, r := range got {
		require.Equal(t, thisRelease(), r, "version %d", v)
	}
}

// An update records this build's release on the versions it adds, and
// leaves the rows it found as they were: a guard updated from the version
// before the release column (13) gets the release on version 14 and every
// later one only.
func TestAnUpdateRecordsTheReleaseOnTheVersionsItAdds(t *testing.T) {
	restore := guardtest.UpToVersion(t, guard.ReleaseVersion-1)
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	restore()
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(1) FROM pg_catalog.pg_attribute
		WHERE attrelid = 'basalt_meta.schema_version'::regclass AND attname = 'release'`), "no release column before its version")

	d.NewAgent(t, "bot", leads, nil) // basalt init over it: the update
	got := releases(t, d.Admin)
	for v, r := range got {
		want := ""
		if v >= guard.ReleaseVersion {
			want = thisRelease()
		}
		require.Equal(t, want, r, "version %d", v)
	}

	// The next update writes its own version's row, and no other.
	d.Exec(t, `SET ROLE `+d.Names.Guard()+`; UPDATE basalt_meta.schema_version SET release = NULL; RESET ROLE`)
	next := guardtest.NextVersion(t, true)
	d.NewAgent(t, "bot", leads, nil)
	got = releases(t, d.Admin)
	require.Equal(t, thisRelease(), got[next])
	require.Equal(t, "", got[next-1])
}

// ReadOldInstall names a guard below the update floor with the release
// recorded with its version, and nothing for a guard at or above it.
func TestReadOldInstall(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 1)
	old := guardtest.New(t).WithDemo(t)
	old.NewAgent(t, "bot", leads, nil)
	restore()
	got, ok, err := guard.ReadOldInstall(ctx, old.Admin)
	require.NoError(t, err)
	require.True(t, ok, "version 1, as every 0.0.1 release left it, is below the floor")
	require.Equal(t, guardmodel.OldInstall{Version: 1, Floor: 2}, got, "no release recorded before the column")

	current := guardtest.New(t).WithDemo(t)
	current.NewAgent(t, "bot", leads, nil)
	_, ok, err = guard.ReadOldInstall(ctx, current.Admin)
	require.NoError(t, err)
	require.False(t, ok, "a guard at this build's version is updated in place")
	_, ok, err = guard.ReadOldInstall(ctx, guardtest.New(t).Admin)
	require.NoError(t, err)
	require.False(t, ok, "no guard")

	// A later breaking release raises the floor above the guard this build
	// installed: its release is named.
	floor := guard.LatestVersion() + 1
	guardtest.WithMigrations(t, guard.TestMigration{Version: floor, SQL: "\nSELECT 1;\n", Reinstall: true})
	got, ok, err = guard.ReadOldInstall(ctx, current.Admin)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, guardmodel.OldInstall{Version: floor - 1, Floor: floor, Release: thisRelease()}, got)
}
