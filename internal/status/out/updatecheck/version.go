package updatecheck

import (
	"strings"

	"golang.org/x/mod/semver"
)

// parseVersion reads "1.2.3", "v1.2.3" or "1.2.3-alpha.2" into the canonical
// "v"-prefixed form golang.org/x/mod/semver compares. Build metadata is
// dropped. It reports false for anything else: shorthand such as "1.2", a
// pseudo-version or a bare commit.
func parseVersion(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	s, _, _ = strings.Cut(s, "+")
	// semver accepts "v1" and "v1.2" as shorthand; Canonical expands them, so
	// a string that changes is not a full version.
	if !semver.IsValid(s) || semver.Canonical(s) != s {
		return "", false
	}
	return s, true
}

func prerelease(v string) bool { return semver.Prerelease(v) != "" }
