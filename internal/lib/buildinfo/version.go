package buildinfo

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// ParseVersion reads "1.2.3", "v1.2.3" or "1.2.3-alpha.2" into the canonical
// "v"-prefixed form CompareVersions takes. Build metadata is dropped. It
// reports false for anything else: shorthand such as "1.2", a pseudo-version
// or a bare commit.
func ParseVersion(s string) (string, bool) {
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

// CompareVersions orders two versions from ParseVersion by semantic version
// precedence, with one rule of ours: a release candidate, whose pre-release
// ends in "-rc.N", sorts below the same version without that suffix, and
// candidates of one version by N. So v0.1.0-alpha-rc.3 is older than
// v0.1.0-alpha, which plain semver would put the other way round.
func CompareVersions(a, b string) int {
	baseA, rcA := splitCandidate(a)
	baseB, rcB := splitCandidate(b)
	if c := semver.Compare(baseA, baseB); c != 0 {
		return c
	}
	switch {
	case rcA < 0 && rcB < 0:
		return 0
	case rcA < 0:
		return 1
	case rcB < 0:
		return -1
	case rcA < rcB:
		return -1
	case rcA > rcB:
		return 1
	}
	return 0
}

// splitCandidate returns v without a trailing "-rc.N" and N, or v and -1 when
// v is not a release candidate.
func splitCandidate(v string) (base string, n int) {
	i := strings.LastIndex(v, "-rc.")
	if i < 0 {
		return v, -1
	}
	n, err := strconv.Atoi(v[i+len("-rc."):])
	if err != nil || n < 0 {
		return v, -1
	}
	return v[:i], n
}
