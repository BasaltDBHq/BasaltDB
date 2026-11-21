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
	pgdial.SetTrust(trustdir.Source(configArg(args, config.DefaultPath(runtime.GOOS))))
}

// configArg is the value of the last -config or --config flag in args,
// before a "--", or def.
func configArg(args []string, def string) string {
	path := def
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
			path = value
		case i+1 < len(args):
			path = args[i+1]
			i++
		}
	}
	return path
}
