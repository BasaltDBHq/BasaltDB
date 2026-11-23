package app

import (
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
)

// useTrustDir makes every connection this process opens trust the
// operator's profiles in trust.d next to the engine config the command
// is in: the one basalt engine names with --config, else the one every
// command finds by itself, with the built-in ones, read again for each
// connection (CONTRACT.md, Trust profiles).
func useTrustDir(args []string) {
	path, given := cli.ConfigArg(args)
	if !given {
		// Both configs found is the command's own error to report; the
		// system one holds the profiles then.
		path, _ = cli.DiscoverConfig(OSHost{}, config.DefaultPath(runtime.GOOS))
		if path == "" {
			path = config.DefaultPath(runtime.GOOS)
		}
	}
	pgdial.SetTrust(trustdir.Source(path))
}
