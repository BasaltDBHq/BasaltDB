package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// approvalCase is the held writes use case: what is held for the person, the
// links that open it, the pending list and the reveal. It holds a reference to
// the shared core group and to its own ApprovalDeps. What it needs from the
// other use cases it names as small ports of its own: the delivery of links
// and notices, the open reverts, the write store's statement check, and the
// call admission.
type approvalCase struct {
	core     *CoreDeps
	deps     *ApprovalDeps
	delivery approvalDelivery
	reverts  approvalReverts
	writes   statementChecker
	admit    admitter
}

// approvalDelivery is what the approval use case asks of the delivery use case.
type approvalDelivery interface {
	approvalReceipt(ctx context.Context, id uuid.UUID) (Receipt, error)
	carriesLarge(cost int64) bool
	columnsOf(ctx context.Context, lines []string) approval.ColumnOrder
	credentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	deliver(n LinkNotice)
	largeShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, cost int64) (string, error)
	pageAddress(page func(string, uuid.UUID) string, id uuid.UUID) string
	pageLink(page func(string, uuid.UUID) string, id uuid.UUID, secret string) string
	shortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error)
	shortLinked(id uuid.UUID) bool
	tooLargeMessage(what string, cost int64, expires time.Time, isRevert bool) string
}

// approvalReverts is what the approval use case reads of the revert use case:
// the open reverts, listed next to the held writes, and the handing over of
// a pending one.
type approvalReverts interface {
	ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error)
	pendingRevert(ctx context.Context, p *PendingRevert, reissue bool) error
}

// admitter admits a call: the engine is set up and its guard is current.
type admitter interface {
	Admit(ctx context.Context) error
}

// serviceReverts is the revert side the approval use case reads, read live
// from the service.
type serviceReverts struct{ s *Service }

func (r serviceReverts) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return r.s.deps.Revert.Store.ListOpenReverts(ctx, p)
}

func (r serviceReverts) pendingRevert(ctx context.Context, p *PendingRevert, reissue bool) error {
	return r.s.pendingRevert(ctx, p, reissue)
}

// liveWrites is the write store's statement check, read live from the service.
type liveWrites struct{ d *WriteDeps }

func (l liveWrites) Check(sql string, tool action.Tool) (action.Statement, error) {
	return l.d.Store.Check(sql, tool)
}

func newApprovalCase(core *CoreDeps, deps *ApprovalDeps, delivery approvalDelivery, reverts approvalReverts, writes statementChecker, admit admitter) *approvalCase {
	return &approvalCase{core: core, deps: deps, delivery: delivery, reverts: reverts, writes: writes, admit: admit}
}

// ApprovalRequest is the approval request of a held write still waiting
// for the person's signature: the JSON the long link carries.
func (s *Service) ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error) {
	return s.approval.ApprovalRequest(ctx, id)
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (s *Service) RelayApproval(ctx context.Context, r approval.Response) (Receipt, error) {
	return s.approval.RelayApproval(ctx, r)
}

// ListPending lists the held writes and open reverts of the agent.
func (s *Service) ListPending(ctx context.Context, p PendingParams) (pagination.Page[PendingEntry], error) {
	return s.approval.ListPending(ctx, p)
}

// RevealApproval reveals the rows of a held write to the page holding secret.
func (s *Service) RevealApproval(ctx context.Context, id uuid.UUID, secret string, in RevealRequest) (approval.RevealAnswer, error) {
	return s.approval.RevealApproval(ctx, id, secret, in)
}
