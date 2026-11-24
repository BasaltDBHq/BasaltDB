package app

import (
	"context"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
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

// agentApprovals is the approval use case as the agent's write use case
// asks it: a held write's request is passed on as its text and parameters.
type agentApprovals struct{ *approvalsvc.Service }

func (a agentApprovals) HoldColumns(ctx context.Context, req agentstore.Request) ([]string, error) {
	return a.Service.HoldColumns(ctx, req.Text, req.Params)
}

func (a agentApprovals) Preview(ctx context.Context, in action.Intent, req agentstore.Request, assigned []string) ([]string, error) {
	return a.Service.Preview(ctx, in, req.Text, req.Params, assigned)
}

// defaultPoll is how often a waiting call reads whether the person signed.
const defaultPoll = time.Second
