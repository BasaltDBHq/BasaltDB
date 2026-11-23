package app

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/status"
)

// portalChecker is the daily portal check (CONTRACT.md, CLI, basalt portal
// verify) as the agents' status reads it.
type portalChecker struct{ *status.Checker }

// PortalFinding is the last check's result for status.
func (p portalChecker) PortalFinding() (agent.PortalFinding, bool) {
	r, ok := p.Last()
	if !ok {
		return agent.PortalFinding{}, false
	}
	return agent.PortalFinding{CheckedAt: r.CheckedAt, Mismatch: r.Mismatch(), Summary: r.Summary()}, true
}

// newPortalChecker is the daily check of the portal the config names, nil
// when it names none: the pages base is the engine's own local pages, which
// are the embedded files themselves and need no check.
func newPortalChecker(pagesBase, stateDir string, log *slog.Logger, now func() time.Time) *portalChecker {
	if pagesBase != links.Portal {
		return nil
	}
	return &portalChecker{status.New(status.Options(pagesBase), stateDir, log.With("component", "portal-check"), now)}
}
