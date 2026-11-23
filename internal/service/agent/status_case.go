package agent

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// statusKeeper is the status use case: the status tool, the call admission, the
// setup the agent waits for and the warnings that come from the guard's state.
// It holds a reference to the shared core group and to its own StatusDeps,
// and owns the pending setup state that used to sit on the service. It reads
// nothing from the other use cases.
type statusKeeper struct {
	core *CoreDeps
	deps *StatusDeps
	// pending is the agent's pending setup and what finishing it keeps.
	pending *setupKeeper
}

func newStatusKeeper(core *CoreDeps, deps *StatusDeps) *statusKeeper {
	return &statusKeeper{core: core, deps: deps, pending: &setupKeeper{setup: deps.Setup}}
}

// The reads the plugin use case makes of the status group, read as it stands.

func (sc *statusKeeper) sameUser() bool { return sc.deps.SameUser }

func (sc *statusKeeper) devLocalPages() bool { return sc.deps.DevLocalPages }

func (sc *statusKeeper) vaultState() string {
	if sc.deps.Vault == nil {
		return vaultStateOff
	}
	return sc.deps.Vault.VaultStatus().State
}

func (sc *statusKeeper) guardStatus(ctx context.Context) (guardmodel.Status, error) {
	return sc.deps.Probe.GuardStatus(ctx)
}

// Status is the status tool: whether the agent is served and each problem
// with its steps. It never fails on what it reads: an unreachable database
// or a missing guard is a problem in the result, not an error. It never
// names the credential file.
// Status is the status use case's Status.
func (s *Service) Status(ctx context.Context) (guidance.StatusReport, error) {
	return s.status.Status(ctx)
}

// Admit refuses a tool call the agent cannot be served yet (CONTRACT.md,
// Next steps, Startup failures): its INSTALL setup code has not run, or
// the guard is not installed or misses a breaking migration. It reads the
// guard on every call, so a guard update needs no engine restart. status is
// never refused.
// Admit is the status use case's Admit.
func (s *Service) Admit(ctx context.Context) error {
	return s.status.Admit(ctx)
}

// AdmitTick is the heartbeat's gate: it first looks for a pending setup of
// any kind in the database, so a rotated credential is picked up and
// engine.json cleared even when nobody calls status, then admits as Admit.
// AdmitTick is the status use case's AdmitTick.
func (s *Service) AdmitTick(ctx context.Context) error {
	return s.status.AdmitTick(ctx)
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
// UpdateNotice is the status use case's UpdateNotice.
func (s *Service) UpdateNotice() string {
	return s.status.UpdateNotice()
}
