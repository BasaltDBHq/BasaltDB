package buildinfo

import (
	"runtime/debug"
	"testing"
)

// The version is this module's: the main module's when basalt is built,
// the dependency's in another program that imports it (the connect
// service), never that program's own.
func TestModuleVersion(t *testing.T) {
	t.Parallel()
	dep := func(path, version string) *debug.Module { return &debug.Module{Path: path, Version: version} }
	replaced := dep(modulePath, "v0.1.0-alpha")
	replaced.Replace = dep("../basaltdb", "(devel)")
	for name, tc := range map[string]struct {
		info debug.BuildInfo
		want string
	}{
		"basalt itself":      {debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v0.1.0-alpha"}}, "v0.1.0-alpha"},
		"basalt from a tree": {debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}, ""},
		"another program": {debug.BuildInfo{
			Main: debug.Module{Path: "example.com/connect", Version: "v1.6.0"},
			Deps: []*debug.Module{dep("golang.org/x/mod", "v0.20.0"), dep(modulePath, "v0.1.0-alpha")},
		}, "v0.1.0-alpha"},
		"another program, replaced": {debug.BuildInfo{
			Main: debug.Module{Path: "example.com/connect", Version: "v1.6.0"}, Deps: []*debug.Module{replaced},
		}, ""},
		"another program without it": {debug.BuildInfo{Main: debug.Module{Path: "example.com/connect", Version: "v1.6.0"}}, ""},
	} {
		if got := moduleVersion(&tc.info); got != tc.want {
			t.Errorf("%s: moduleVersion = %q, want %q", name, got, tc.want)
		}
	}
}
