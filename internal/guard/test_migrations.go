package guard

import "fmt"

// TestMigration is a version a test appends after this build's own. The
// tests of the upgrade machinery (basalt upgrade, the stale-version check, breaking and
// non-breaking versions, setup codes that upgrade) add theirs through
// AppendTestMigrations. No product code calls it.
type TestMigration struct {
	Version     int
	SQL         string
	NonBreaking bool
}

// AppendTestMigrations appends ms to the versions this build installs until
// the returned restore runs. Each version must follow the one before it.
// It changes package state every guard call reads, so only
// guardtest.WithMigrations calls it, from a test that never runs in
// parallel with another.
func AppendTestMigrations(ms ...TestMigration) (restore func()) {
	saved := migrations
	next := append([]migration(nil), migrations...)
	for _, m := range ms {
		if want := next[len(next)-1].version + 1; m.Version != want {
			panic(fmt.Sprintf("test migration %d: want version %d", m.Version, want))
		}
		next = append(next, migration{version: m.Version, sql: m.SQL, nonBreaking: m.NonBreaking})
	}
	migrations = next
	return func() { migrations = saved }
}

// KeepTestMigrationsUpTo installs only the versions up to v until the
// returned restore runs, so a test can install a guard as an earlier
// release did and then upgrade it. Like AppendTestMigrations, only
// guardtest calls it, from a test that never runs in parallel.
func KeepTestMigrationsUpTo(v int) (restore func()) {
	if v < versionGuard || v > LatestVersion() {
		panic(fmt.Sprintf("keep test migrations up to %d: want 1 to %d", v, LatestVersion()))
	}
	saved := migrations
	migrations = append([]migration(nil), migrations[:v]...)
	return func() { migrations = saved }
}
