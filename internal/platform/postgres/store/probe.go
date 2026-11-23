package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// Probe is the guard probe (agent.Probe) on an agent connection or pool, against the build's
// migrations (guard.Migrations outside tests).
type Probe struct {
	Q          guard.Querier
	Migrations []guardmodel.Migration
	// Kept is the engine's kept copy of the pins it set aside (its pin
	// file's setAside); nil when there is none to read.
	Kept func() []action.SetAside
}

// guardStatusRaw is GuardStatus before MapError.
func (p Probe) guardStatusRaw(ctx context.Context) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, p.Q, p.Migrations)
}

// setupRecordedRaw is SetupRecorded before MapError.
func (p Probe) setupRecordedRaw(ctx context.Context, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, p.Q, id)
}

// latestSetupRaw is LatestSetup before MapError.
func (p Probe) latestSetupRaw(ctx context.Context) (guardmodel.AgentSetup, bool, error) {
	return guard.LatestAgentSetup(ctx, p.Q)
}

// ledgerBytesRaw is LedgerBytes before MapError.
func (p Probe) ledgerBytesRaw(ctx context.Context) (int64, error) {
	return guard.LedgerBytes(ctx, p.Q)
}

// reinstallsRaw is Reinstalls before MapError.
func (p Probe) reinstallsRaw(ctx context.Context) (guard.Reinstalls, error) {
	var kept []guard.SetAside
	if p.Kept != nil {
		kept = GuardSetAside(p.Kept())
	}
	return guard.ReadReinstalls(ctx, p.Q, kept)
}

// GuardSetAside is the guard's form of pins set aside (chainpin keeps them
// in action types), nil for nil.
func GuardSetAside(kept []action.SetAside) []guard.SetAside {
	return mapSlice(kept, func(k action.SetAside) guard.SetAside { return guard.SetAside(k) })
}
