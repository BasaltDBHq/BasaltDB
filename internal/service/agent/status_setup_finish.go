package agent

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// Finishing a setup from the laptop (CONTRACT.md, Setup from your laptop, On
// the engine). On status, on every call while an INSTALL setup holds the
// tools, and at each heartbeat, the engine logs in with the agent's own
// credential (the .pending one first) and looks for the pending setupId in
// basalt_meta.agent_setups. Found: the setup is DONE (RI-10). The engine
// promotes the .pending credential when that is the one that found it,
// clears setup from engine.json, and serves the agent, with no restart. The
// guard version, the grants and the passkeys stay status's usual problems
// (GUARD_OUTDATED, PERMISSION_DENIED on use, NO_PASSKEY), not conditions for
// DONE. Nothing the agent or a client says is taken as proof: only the
// database, read as the agent.

// AdmitTick is the heartbeat's gate: it first looks for a pending setup of
// any kind in the database, so a rotated credential is picked up and
// engine.json cleared even when nobody calls status, then admits as Admit.
func (sc *statusKeeper) AdmitTick(ctx context.Context) error {
	if w := sc.setupWatch(); w.Setup != nil && w.Setup.Kind != guardmodel.SetupInstall {
		w.PendingRecorded(ctx)
	}
	return sc.Admit(ctx)
}

// setupWatch is the pending setup as a call reads it now.
func (sc *statusKeeper) setupWatch() handoff.SetupWatch {
	return handoff.SetupWatch{
		Setup: sc.pending.Pending(), Database: sc.deps.Database, Probe: sc.deps.Probe, Finisher: sc.deps.Finisher,
		Finished: sc.pending.Finished, NotRecorded: &sc.pending.NotRecorded, LockTrouble: &sc.pending.LockTrouble,
		Log: sc.core.Log, Now: sc.core.Now,
	}
}
