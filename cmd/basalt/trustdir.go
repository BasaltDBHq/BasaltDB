package main

import (
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/config"
)

// useTrustDir makes every connection this process opens trust the
// operator's profiles in trust.d next to the engine config the command
// is in: the one basalt engine names with --config, else the one every
// command finds by itself, with the built-in ones, read again for each
// connection (CONTRACT.md, Trust profiles).
func useTrustDir(args []string) {
	path, given := configArg(args)
	if !given {
		// Both configs found is the command's own error to report; the
		// system one holds the profiles then.
		path, _ = discoverConfig(osHost{}, config.DefaultPath(runtime.GOOS))
		if path == "" {
			path = config.DefaultPath(runtime.GOOS)
		}
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
