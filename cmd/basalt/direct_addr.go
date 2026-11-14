package main

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// flagDirectAddr is init's and init --remote's flag for directAddr in
// engine.json (CONTRACT.md, Direct transport).
const flagDirectAddr = "direct-addr"

const directAddrUsage = "host:port or off: the loopback address the engine listens on for your tunnel to forward to " +
	"(CONTRACT.md, Direct transport; with --operated-by=agent or --remote only; the engine binds it at its next start)"

// checkDirectAddr is --direct-addr's value checked as the engine checks
// directAddr at load: off, or a literal loopback IP and a port. Anything
// else is a usage error (exit 2) before anything is written.
func checkDirectAddr(v string) error {
	if v == "" {
		return fmt.Errorf("%w: --%s needs host:port or off", errUsage, flagDirectAddr)
	}
	if _, err := (config.Config{PagesURL: links.Portal, DirectAddr: v}).Direct(); err != nil {
		return fmt.Errorf("%w: --%s %q: use off, or a loopback address such as 127.0.0.1:8787 (%s needs a loopback IP and a port; your tunnel reaches it)",
			errUsage, flagDirectAddr, v, flagDirectAddr)
	}
	return nil
}
