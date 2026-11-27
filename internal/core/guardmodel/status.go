package guardmodel

import "time"

// DeadManAfter is how long without an engine heartbeat before the engine,
// checking in again, records that it was silent (D14), and before basalt
// log warns that the engine stopped checking in; basalt log also keeps
// showing the DEAD_MAN row of that span. Nothing gets disabled.
const DeadManAfter = 7 * 24 * time.Hour

// Guard states the status tool reports (api/mcp/tools/status.json, guard.state).
const (
	GuardOK               = "OK"
	GuardUpgradeAvailable = "UPGRADE_AVAILABLE"
	GuardOutdated         = "OUTDATED"
	GuardNewer            = "NEWER"
	GuardMissing          = "MISSING"
	GuardUnknown          = "UNKNOWN"
)

// Migration is one basalt_meta version this build installs and whether an
// engine can serve an agent without it (CONTRACT.md, basalt_meta, AE-11).
type Migration struct {
	Version  int
	Breaking bool
}

// Status is the guard as an agent connection sees it, against a build's
// migrations.
type Status struct {
	State string
	// Installed is the newest installed version (0 without basalt_meta).
	Installed int
	// Build is the newest version of the build's migrations.
	Build              int
	MissingBreaking    []int
	MissingNonBreaking []int
	// BelowFloor: Installed is below the build's update floor, so the guard
	// cannot be updated in place (an install from 0.0.1). The State is then
	// OUTDATED, and the person removes the install and sets up again
	// (RemoveOldInstallDoc) instead of updating it.
	BelowFloor bool
}

// RemoveOldInstallDoc is the page that says how to remove an older
// BasaltDB install from a database.
const RemoveOldInstallDoc = "https://github.com/BasaltDBHq/BasaltDB/blob/master/docs/remove-old-install.md"

// Served reports whether an engine serves the agent's tools on this guard:
// nothing breaking is missing.
func (s Status) Served() bool {
	return s.State != GuardOutdated && s.State != GuardMissing && s.State != GuardUnknown
}
