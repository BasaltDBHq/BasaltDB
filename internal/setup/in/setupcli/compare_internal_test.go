package setupcli

import (
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// Not parallel: it sets the build version the process reports.
func TestNewerThanEngine(t *testing.T) {
	old := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = old })
	for _, v := range []struct {
		this, engine string
		newer, fails bool
	}{
		{"0.1.0-alpha", "", true, false},                 // an engine that sends no build is older
		{"0.1.0-alpha", "0.1.0-alpha-rc.3", true, false}, // the release over its candidate: copy, no refusal
		{"0.1.0-alpha-rc.3", "0.1.0-alpha", false, true}, // never back to a candidate
		{"0.1.0-alpha-rc.3", "0.1.0-alpha-rc.2", true, false},
		{"v0.1.0", "0.1.0", false, false}, // the same version spelled apart
		{"0.1.0", "0.1.0+build5", false, false},
		{"0.1.0-alpha", "0.1.0-beta", false, true},
		{"0.2.0", "0.10.0", false, true},
		{"0.1.0-alpha", "abc123", false, true}, // order cannot be told
		{"abc123", "0.1.0", false, true},
		{"0.1.0", "0.1", false, true},
	} {
		buildinfo.Version = v.this
		newer, err := newerThanEngine(v.engine)
		if newer != v.newer || (err != nil) != v.fails {
			t.Errorf("newerThanEngine(this %q, engine %q) = %v, %v; want %v, fails %v", v.this, v.engine, newer, err, v.newer, v.fails)
		}
	}
}
