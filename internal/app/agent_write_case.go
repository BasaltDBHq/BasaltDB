package app

import (
	"context"

	"github.com/google/uuid"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
)

// StartRun starts a run with intent. taskID joins a task another agent
// started; uuid.Nil starts a new task.
func (s *Service) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (agentsvc.RunInfo, error) {
	return s.agent.StartRun(ctx, intent, taskID)
}

// Query checks sql against the policy, runs it read-only within the limits
// and records the read with the version of each row it could identify. A
// refused or failed statement is recorded as a REFUSED change. A read that
// cannot be recorded is not returned: the ledger must know what the agent
// saw.
func (s *Service) Query(ctx context.Context, p agentsvc.QueryParams) (agentsvc.QueryOutcome, error) {
	return s.agent.Query(ctx, p)
}

// Write checks sql against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
func (s *Service) Write(ctx context.Context, p agentsvc.WriteParams) (agentsvc.WriteOutcome, error) {
	return s.agent.Write(ctx, p)
}
