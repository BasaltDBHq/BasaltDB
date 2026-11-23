package app

import (
	"context"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
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

// RevealApproval reveals the rows of a held write to the page holding secret.
func (s *Service) RevealApproval(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return s.approval.RevealApproval(ctx, id, secret, in)
}

// liveWrites is the write store's statement check, read live from the service.
type liveWrites struct{ d *agentsvc.WriteDeps }

func (l liveWrites) Check(sql string, tool action.Tool) (action.Statement, error) {
	return l.d.Store.Check(sql, tool)
}

// DefaultPoll is how often a waiting call reads whether the person signed.
const DefaultPoll = time.Second
