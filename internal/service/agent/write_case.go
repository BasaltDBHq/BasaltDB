package agent

import (
	"context"

	"github.com/google/uuid"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
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

// History returns one page of a run's change records.
func (s *Service) History(ctx context.Context, p action.ChangeListParams) (History, error) {
	return s.ledger.History(ctx, p)
}

// ListRuns returns one page of the agent's own runs with what each did.
func (s *Service) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return s.agent.ListRuns(ctx, p)
}

// Write checks sql against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
func (s *Service) Write(ctx context.Context, p agentsvc.WriteParams) (agentsvc.WriteOutcome, error) {
	return s.agent.Write(ctx, p)
}
