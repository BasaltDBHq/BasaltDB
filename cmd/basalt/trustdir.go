package main

import (
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
)

// useTrustDir makes every connection this process opens trust the
// operator's profiles in trust.d next to the engine config the command
// names with --config (the default config otherwise), with the built-in
// ones, read again for each connection (CONTRACT.md, Trust profiles).
func useTrustDir(args []string) {
	path, given := configArg(args)
	if !given {
		// As the person commands find their config (configOrFallback): the
		// per-user config init left when nothing is installed system-wide.
		path = perUserConfigFallback(osHost{}, config.DefaultPath(runtime.GOOS))
	}
	pgdial.SetTrust(trustdir.Source(path))
}

// configArg is the value of the last -config or --config flag in args,
// before a "--", and whether there is one.
func configArg(args []string) (string, bool) {
	path, given := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		switch {
		case inline:
			path, given = value, true
		case i+1 < len(args):
			path, given = args[i+1], true
			i++
		}
	}
	return path, given
}
