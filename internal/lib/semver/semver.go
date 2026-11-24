// Package semver parses and orders semantic versions, as basalt builds and
// release tags spell them.
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed semantic version: major.minor.patch with optional
// dot-separated pre-release identifiers (build metadata is dropped).
type Version struct {
	Core [3]uint64
	Pre  []string
}

// Parse reads "1.2.3", "v1.2.3" or "1.2.3-alpha.2". It reports false for
// anything else, such as a bare commit.
func Parse(s string) (Version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	var v Version
	if len(parts) != len(v.Core) {
		return Version{}, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 63)
		if err != nil {
			return Version{}, false
		}
		v.Core[i] = n
	}
	if hasPre {
		if pre == "" {
			return Version{}, false
		}
		v.Pre = strings.Split(pre, ".")
		for _, id := range v.Pre {
			if !validIdentifier(id) {
				return Version{}, false
			}
		}
	}
	return v, true
}

// Prerelease reports whether v has pre-release identifiers.
func (v Version) Prerelease() bool { return len(v.Pre) > 0 }

// Compare returns -1, 0 or 1 by semantic version precedence.
func (v Version) Compare(o Version) int {
	for i := range v.Core {
		if c := cmpUint(v.Core[i], o.Core[i]); c != 0 {
			return c
		}
	}
	switch {
	case !v.Prerelease() && !o.Prerelease():
		return 0
	case !v.Prerelease():
		return 1
	case !o.Prerelease():
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		if c := comparePre(v.Pre[i], o.Pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.Pre)), uint64(len(o.Pre)))
}

// CompareStrings compares two version strings by precedence; ok is false
// when either does not parse.
func CompareStrings(a, b string) (c int, ok bool) {
	va, okA := Parse(a)
	vb, okB := Parse(b)
	if !okA || !okB {
		return 0, false
	}
	return va.Compare(vb), true
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

// validIdentifier is true for a non-empty pre-release identifier made of
// [0-9A-Za-z-].
func validIdentifier(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
			return false
		}
	}
	return true
}
