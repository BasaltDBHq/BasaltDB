package app

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/status"
)

// newPortalChecker is the daily check of the portal the config names, nil
// when it names none: the pages base is the engine's own local pages, which
// are the embedded files themselves and need no check.
func newPortalChecker(pagesBase, stateDir string, log *slog.Logger, now func() time.Time) *status.Checker {
	if pagesBase != links.Portal {
		return nil
	}
	return status.NewChecker(status.PortalcheckOptions(pagesBase), stateDir, log.With("component", "portal-check"), now)
}
