package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// writeCase is the query and write use case: runs, reads, writes and the
// holding of a write for the person's approval. It holds a reference to the
// shared core group and to its own WriteDeps. What it needs from the other use
// cases it names as small ports of its own.
type writeCase struct {
	core      *CoreDeps
	deps      *WriteDeps
	delivery  writeDelivery
	approvals writeApprovals
	upgrade   upgradeWarner
	next      approvalLinker
}

// writeDelivery is what the write use case asks of the delivery use case.
type writeDelivery interface {
	approvalReceiptOf(a action.Approval) (Receipt, error)
	awaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error
	deliverHeld(id uuid.UUID, expires time.Time, answer error)
	notifyHeldTo(ctx context.Context, n HeldNotice) error
}

// writeApprovals is what the write use case asks of the approval use case: to
// hold a write and to read it back.
type writeApprovals interface {
	approvalNotice(ctx context.Context, id, runID uuid.UUID, req sizedRequest, expires time.Time, issue bool) (heldNotice, error)
	HoldColumns(ctx context.Context, sql string, params []any) ([]string, error)
	Preview(ctx context.Context, in action.Intent, sql string, params []any, assigned []string) ([]string, error)
	Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error)
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	// notFound is the ledger's answer for an approval the role does not hold.
	notFound() error
}

// upgradeWarner gives the warnings of a guard that can be upgraded, for run_start.
type upgradeWarner interface {
	upgradeWarnings(ctx context.Context) []toolresult.Warning
}

// approvalLinker puts the link of a held write into an error answer.
type approvalLinker interface {
	approvalLinkError(te *toolresult.ToolError, n heldNotice) *toolresult.ToolError
}

func newWriteCase(core *CoreDeps, deps *WriteDeps, delivery writeDelivery, approvals writeApprovals, upgrade upgradeWarner, next approvalLinker) *writeCase {
	return &writeCase{core: core, deps: deps, delivery: delivery, approvals: approvals, upgrade: upgrade, next: next}
}

// StartRun starts a run with intent. taskID joins a task another agent
// started; uuid.Nil starts a new task.
// StartRun is the write use case's StartRun.
func (s *Service) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	return s.write.StartRun(ctx, intent, taskID)
}

// Query checks sql against the policy, runs it read-only within the limits
// and records the read with the version of each row it could identify. A
// refused or failed statement is recorded as a REFUSED change. A read that
// cannot be recorded is not returned: the ledger must know what the agent
// saw.
// Query is the write use case's Query.
func (s *Service) Query(ctx context.Context, p QueryParams) (QueryOutcome, error) {
	return s.write.Query(ctx, p)
}

// History returns one page of a run's change records.
// History is the write use case's History.
func (s *Service) History(ctx context.Context, p action.ChangeListParams) (History, error) {
	return s.write.History(ctx, p)
}

// ListRuns returns one page of the agent's own runs with what each did.
// ListRuns is the write use case's ListRuns.
func (s *Service) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return s.write.ListRuns(ctx, p)
}

// Write checks sql against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
// Write is the write use case's Write.
func (s *Service) Write(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	return s.write.Write(ctx, p)
}
