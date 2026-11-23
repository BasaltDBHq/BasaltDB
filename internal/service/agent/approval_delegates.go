package agent

import (
	"context"
	"time"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// ApprovalRequest is the approval request of a held write still waiting
// for the person's signature: the JSON the long link carries.
func (s *Service) ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error) {
	return s.approval.ApprovalRequest(ctx, id)
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (s *Service) RelayApproval(ctx context.Context, r approval.Response) (linksvc.Receipt, error) {
	return s.approval.RelayApproval(ctx, r)
}

// ListPending lists the held writes and open reverts of the agent.
func (s *Service) ListPending(ctx context.Context, p approvalsvc.PendingParams) (pagination.Page[approvalsvc.PendingEntry], error) {
	return s.approval.ListPending(ctx, p)
}

// RevealApproval reveals the rows of a held write to the page holding secret.
func (s *Service) RevealApproval(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return s.approval.RevealApproval(ctx, id, secret, in)
}

// liveWrites is the write store's statement check, read live from the service.
type liveWrites struct{ d *WriteDeps }

func (l liveWrites) Check(sql string, tool action.Tool) (action.Statement, error) {
	return l.d.Store.Check(sql, tool)
}

// DefaultPoll is how often a waiting call reads whether the person signed.
const DefaultPoll = time.Second
