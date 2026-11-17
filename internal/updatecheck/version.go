package updatecheck

import (
	"strconv"
	"strings"
)

// version is a parsed semantic version: major.minor.patch with optional
// dot-separated pre-release identifiers (build metadata is dropped).
type version struct {
	core [3]uint64
	pre  []string
}

// parseVersion reads "1.2.3", "v1.2.3" or "1.2.3-alpha.2". It reports false
// for anything else, such as a pseudo-version or a bare commit.
func parseVersion(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	var v version
	if len(parts) != len(v.core) {
		return version{}, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 63)
		if err != nil {
			return version{}, false
		}
		v.core[i] = n
	}
	if hasPre {
		if pre == "" {
			return version{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func (v version) prerelease() bool { return len(v.pre) > 0 }

// compare returns -1, 0 or 1 by semantic version precedence.
func (v version) compare(o version) int {
	for i := range v.core {
		if c := cmpUint(v.core[i], o.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case !v.prerelease() && !o.prerelease():
		return 0
	case !v.prerelease():
		return 1
	case !o.prerelease():
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := comparePre(v.pre[i], o.pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.pre)), uint64(len(o.pre)))
}

// comparePre orders two pre-release identifiers: numbers numerically and
// below text, text by bytes.
func comparePre(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 63)
	bn, berr := strconv.ParseUint(b, 10, 63)
	switch {
	case aerr == nil && berr == nil:
		return cmpUint(an, bn)
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
