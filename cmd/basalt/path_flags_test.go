package main

import (
	"reflect"
	"runtime"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// Commands no longer take --config, --socket-dir or --credential-file: they
// find the engine config by themselves. Tests that point a command at
// temporary files give the flags to the helper, which moves them into the
// command's path overrides.
//
// The commands another change removes still take --config themselves, so
// the helper leaves their arguments alone.
var keepsConfigFlag = []string{"runLog", "runAccess", "runRevert", "runStatus"}

// takePathFlags removes --config, --socket-dir and --credential-file (and
// their values) from args and sets them on c, unless the command named by
// fn still takes them.
func takePathFlags(c *cli.IO, fn any, args []string) []string {
	name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	name = name[strings.LastIndex(name, ".")+1:]
	return takePathFlagsFor(c, slices.Contains(keepsConfigFlag, name), args)
}

// takePathFlagsFor is takePathFlags for a command known by name: keep is
// true when the command still takes --config.
func takePathFlagsFor(c *cli.IO, keep bool, args []string) []string {
	if keep {
		return args
	}
	var out []string
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		if !inline && i+1 < len(args) {
			value = args[i+1]
		}
		switch name {
		case "--config":
			c.Paths.Config = value
		case "--socket-dir":
			c.Paths.SocketDir = value
		case "--credential-file":
			c.Paths.CredFile = value
		default:
			out = append(out, args[i])
			continue
		}
		if !inline {
			i++
		}
	}
	return out
}
