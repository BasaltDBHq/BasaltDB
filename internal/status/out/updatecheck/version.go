package updatecheck

import "github.com/basaltdbhq/basaltdb/internal/lib/semver"

// version is a parsed semantic version (semver.Version).
type version = semver.Version

// parseVersion reads "1.2.3", "v1.2.3" or "1.2.3-alpha.2" (semver.Parse).
func parseVersion(s string) (version, bool) { return semver.Parse(s) }
