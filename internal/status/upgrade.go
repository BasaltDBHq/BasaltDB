package status

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// UpgradeChecker says whether the guard misses only non-breaking migrations,
// so everything works and the setup page's update adds them. The default asks the
// service's Probe.
type UpgradeChecker interface {
	UpgradeAvailable(ctx context.Context) (bool, error)
}

// UpgradeWarnings is the GUARD_UPGRADE_AVAILABLE warning of run_start, when
// only non-breaking guard migrations are missing.
func (sc *Service) UpgradeWarnings(ctx context.Context) []toolresult.Warning {
	available, err := sc.deps.Upgrade.UpgradeAvailable(ctx)
	if err != nil {
		sc.core.Log.Error("check for a guard upgrade", "err", err)
		return nil
	}
	if !available {
		return nil
	}
	b := guidance.NewSteps()
	person := upgradeSteps(b, sc.core.Commands)
	steps, err := b.Build()
	if err != nil {
		sc.core.Log.Error("cannot build the guard upgrade warning", "err", err)
		return nil
	}
	return []toolresult.Warning{{
		Code:          toolresult.WarningGuardUpgradeAvailable,
		Message:       "the guard in this database misses non-breaking migrations; everything works, the person can upgrade when it suits them",
		PersonMessage: person,
		NextSteps:     steps,
	}}
}

// upgradeSteps: the person adds the missing non-breaking migrations when it
// suits them, in a warning and in status, on the page basalt init links to.
func upgradeSteps(b *guidance.Steps, cmds guidance.Commands) string {
	b.AskPerson("Tell the person the guard can be updated when it suits them, and ask whether to do it now.")
	if cmds.UpdateLinkURL() != "" && !cmds.AgentOperated() {
		b.OpenLink(cmds.UpdateLinkURL(), "On the person's yes, show them this link: nothing stops, and the agent needs no restart.")
		return "The guard in this database can be updated. Everything works as it is; when it suits you, open the link the agent gives you to update it."
	}
	b.AgentRunCommand(cmds.Init(), "On the person's yes, run this and show them the link it prints: nothing stops, and the agent needs no restart.")
	return "The guard in this database can be updated. Everything works as it is; when it suits you, tell the agent: it gives you a link to update it."
}
