package guardmodel

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
}

// Served reports whether an engine serves the agent's tools on this guard:
// nothing breaking is missing.
func (s Status) Served() bool {
	return s.State != GuardOutdated && s.State != GuardMissing && s.State != GuardUnknown
}
