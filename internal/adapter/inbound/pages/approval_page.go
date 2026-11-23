package pages

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// approvalPage serves the approval page's API on the server's agents.
type approvalPage struct{ s *Server }

// NewApprovalHandlers are the approval routes' handlers on s's agents, for
// s.MountApprovals.
func NewApprovalHandlers(s *Server) ApprovalHandlers {
	p := approvalPage{s: s}
	return ApprovalHandlers{Get: p.getApproval, Approve: p.postApproval, Reveal: p.postApprovalReveal}
}

func (p approvalPage) getApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, ApprovalParam)
	if !ok {
		return
	}
	req, err := Find(r.Context(), p.s, func(ctx context.Context, a Agent) (approval.Request, error) { return a.ApprovalRequest(ctx, id) })
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, req)
}

func (p approvalPage) postApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, ApprovalParam)
	if !ok {
		return
	}
	body, ok := p.s.Body(w, r)
	if !ok {
		return
	}
	resp, err := approval.DecodeResponse(body)
	if err != nil || resp.ApprovalID != id {
		p.s.Fail(w, &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: "the body is not this approval's signed response"})
		return
	}
	receipt, err := Find(r.Context(), p.s, func(ctx context.Context, a Agent) (agent.Receipt, error) { return a.RelayApproval(ctx, resp) })
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, approvedDTO{ApprovalID: id.String(), Status: "APPROVED", Receipt: receipt.Token, NoReceipt: receipt.Missing})
}

// approvedDTO is the relay's answer for an approval, with the engine's
// receipt or why there is none.
type approvedDTO struct {
	ApprovalID string `json:"approvalId"`
	Status     string `json:"status"`
	Receipt    string `json:"receipt,omitempty"`
	NoReceipt  string `json:"noReceipt,omitempty"`
}

// postApprovalReveal shows the person the values of the approval's
// redacted lines (Server.Reveal).
func (p approvalPage) postApprovalReveal(w http.ResponseWriter, r *http.Request) {
	p.s.Reveal(w, r, ApprovalParam, func(ctx context.Context, a Agent, id uuid.UUID, secret string, in agent.RevealRequest) (approval.RevealAnswer, error) {
		return a.RevealApproval(ctx, id, secret, in)
	})
}
