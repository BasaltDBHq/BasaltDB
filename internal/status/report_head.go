package status

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// Head is what the report of an agent whose engine answers starts with:
// the agent, who operates it, the engine, the pages and the Vault.
type Head struct {
	Agent, OperatedBy string
	// SameUser: the engine runs as the person's own OS user.
	SameUser bool
	// Build is the engine's build; StartedBy why it started (hand, mcp or
	// crash).
	Build, StartedBy string
	// PagesBase is where the pages' links point (links.DefaultLocal when
	// empty); PagesOrigin the origin of the local pages when served.
	PagesBase, PagesOrigin string
	Vault                  VaultReporter
}

// report is the report's head, before the guard, the setup and the
// problems are known.
func (h Head) report() guidance.StatusReport {
	base := h.PagesBase
	if base == "" {
		base = links.DefaultLocal
	}
	r := guidance.StatusReport{
		Agent: h.Agent, OperatedBy: OperatedBy(h.OperatedBy), Enforcement: Enforcement(h.OperatedBy, h.SameUser),
		Engine: guidance.EngineStatus{Reachable: true, Build: h.Build, StartedBy: StartedByEnum(h.StartedBy)},
		Pages:  guidance.PagesStatus{Served: h.PagesOrigin != "", URL: base},
	}
	if h.Vault != nil {
		v := h.Vault.VaultStatus()
		r.Vault = &v
	}
	return r
}

// finish sorts ps into r's problems and says whether the agent is ready.
func finish(r guidance.StatusReport, ps guidance.Problems) (guidance.StatusReport, error) {
	list, err := ps.Sorted()
	if err != nil {
		return guidance.StatusReport{}, err
	}
	r.Problems, r.Ready = list, Ready(list)
	return r, nil
}

// ConnectOnly is the status of a connect-only agent: the engine answers,
// the guard is UNKNOWN (no credential yet), and the setup says where the
// hand-off st stands at now. cmds are the agent's commands for its
// operator; latestGuard is the basalt_meta version this build installs.
func ConnectOnly(h Head, cmds guidance.Commands, connectBudget, latestGuard int, st handoff.State, now time.Time) (guidance.StatusReport, error) {
	r := h.report()
	r.Guard = guidance.GuardStatus{State: guardmodel.GuardUnknown, Build: latestGuard}
	ps := guidance.Problems{Cmds: cmds, ConnectBudget: connectBudget}
	r.Setup = handoff.ConnectOnlyProblems(st, &ps, now)
	return finish(r, ps)
}
