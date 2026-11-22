// Package buildinfo holds the version printed by `basalt version` and
// reported to MCP clients.
package buildinfo

import "runtime/debug"

const defaultVersion = "0.0.0-dev"

// Version is the build version. Release builds override it with
// -ldflags -X github.com/basaltdbhq/basaltdb/internal/lib/buildinfo.Version=<tag>.
// go install leaves the default; init then fills the module version from
// build info when there is one.
var Version = defaultVersion

func init() {
	if Version != defaultVersion {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return
	}
	Version = v
}
