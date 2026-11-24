package semver_test

import (
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/lib/semver"
)

func TestCompareStrings(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"0.1.0-alpha", "0.1.0-alpha.rc.2", -1, true},
		{"v0.1.0", "0.1.0", 0, true},
		{"0.1.0", "0.1.0-alpha", 1, true},
		{"0.0.0-0", "0.0.0-dev", -1, true},
		{"0.2.0", "0.10.0", -1, true},
		{"abc123", "0.1.0", 0, false},
		{"0.1.0", "", 0, false},
	} {
		got, ok := semver.CompareStrings(v.a, v.b)
		if got != v.want || ok != v.ok {
			t.Errorf("CompareStrings(%q, %q) = %d, %v; want %d, %v", v.a, v.b, got, ok, v.want, v.ok)
		}
	}
}
