package app

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/status"
	"github.com/basaltdbhq/basaltdb/internal/status/out/portalfetch"
)

// newPortalChecker is the daily check of the portal the config names, nil
// when it names none: the pages base is the engine's own local pages, which
// are the embedded files themselves and need no check.
func newPortalChecker(pagesBase, stateDir string, log *slog.Logger, now func() time.Time) *status.Checker {
	if pagesBase != links.Portal {
		return nil
	}
	return status.NewChecker(PortalcheckOptions(pagesBase), stateDir, log.With("component", "portal-check"), now)
}

// PortalcheckOptions is what the portal check compares for base, the
// portal's origin, fetched over HTTPS (portalfetch): the engine's daily
// check and scripts/portal-verify use the same.
func PortalcheckOptions(base string) status.PortalverifyOptions {
	return status.PortalcheckOptions(base, portalfetch.New(base))
}
