// Package buildinfo holds the version printed by `basalt version` and
// reported to MCP clients.
package buildinfo

import (
	"reflect"
	"runtime/debug"
	"strings"
)

const defaultVersion = "0.0.0-dev"

// Version is the build version. Release builds override it with
// -ldflags -X github.com/basaltdbhq/basaltdb/internal/lib/buildinfo.Version=<tag>.
// go install leaves the default; init then fills the module version from
// build info when there is one. In another program that imports this
// module (the connect service, through pkg/setup) it is this module's
// version as that program's build requires it, never that program's own.
var Version = defaultVersion

// marker is a type of this package, whose path names the module.
type marker struct{}

// modulePath is this module's path: this package's, without its own
// folder inside the module.
var modulePath = strings.TrimSuffix(reflect.TypeFor[marker]().PkgPath(), "/internal/lib/buildinfo")

func init() {
	if Version != defaultVersion {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := moduleVersion(info); v != "" {
		Version = v
	}
}

// moduleVersion is this module's version in info: the main module's when
// this module is the main one, else the dependency's (its replacement's
// when it is replaced); "" when unknown.
func moduleVersion(info *debug.BuildInfo) string {
	m := &info.Main
	if m.Path != modulePath {
		m = nil
		for _, d := range info.Deps {
			if d.Path == modulePath {
				m = d
			}
		}
	}
	if m != nil && m.Replace != nil {
		m = m.Replace
	}
	if m == nil || m.Version == "" || m.Version == "(devel)" {
		return ""
	}
	return m.Version
}
