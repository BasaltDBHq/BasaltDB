package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Probe is the guard probe (agent.Probe) on an agent connection or pool, against the build's
// migrations (guard.Migrations outside tests).
type Probe struct {
	Q          guard.Querier
	Migrations []guard.Migration
	// Kept is the engine's kept copy of the pins it set aside (its pin
	// file's setAside); nil when there is none to read.
	Kept func() []action.SetAside
}

// GuardStatus reads schema_version.
func (p Probe) GuardStatus(ctx context.Context) (guard.Status, error) {
	return guard.AgentStatus(ctx, p.Q, p.Migrations)
}

// SetupRecorded reports whether setup id is recorded.
func (p Probe) SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, p.Q, id)
}

// LatestSetup is the agent's newest recorded setup.
func (p Probe) LatestSetup(ctx context.Context) (guard.AgentSetup, bool, error) {
	return guard.LatestAgentSetup(ctx, p.Q)
}

// LedgerBytes is the size of basalt_meta.
func (p Probe) LedgerBytes(ctx context.Context) (int64, error) {
	return guard.LedgerBytes(ctx, p.Q)
}

// Reinstalls reads agent_reinstalls with the kept copy merged in.
func (p Probe) Reinstalls(ctx context.Context) (guard.Reinstalls, error) {
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
