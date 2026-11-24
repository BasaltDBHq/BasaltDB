package buildinfo

import "testing"

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3": "v1.2.3", "v1.2.3": "v1.2.3", "1.2.3-alpha.2": "v1.2.3-alpha.2", "v1.2.3+build5": "v1.2.3",
	} {
		if got, ok := ParseVersion(in); !ok || got != want {
			t.Errorf("ParseVersion(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "1", "v1", "1.2", "v1.2", "dev", "abc123", "1.2.x", "1.2.3-", "v1.2.3.4"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	// Each version is older than the next.
	order := []string{
		"0.0.1-alpha.1", "0.0.1-alpha.2", "0.0.1-alpha.10", "0.0.1-beta", "0.0.1", "0.0.2",
		"0.1.0-alpha-rc.1", "0.1.0-alpha-rc.2", "0.1.0-alpha-rc.3", "0.1.0-alpha", "0.1.0-beta", "0.1.0-rc.1", "0.1.0", "1.0.0",
	}
	for i := range order {
		for j := range order {
			a, _ := ParseVersion(order[i])
			b, _ := ParseVersion(order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := CompareVersions(a, b); got != want {
				t.Errorf("%s vs %s = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if a, _ := ParseVersion("0.1.0-alpha-rc.10"); CompareVersions(a, "v0.1.0-alpha-rc.9") <= 0 {
		t.Error("rc.10 is newer than rc.9")
	}
}
