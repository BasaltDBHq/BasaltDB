package agent

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalRequest is the approval request of a held write still waiting
// for the person's signature: the JSON the long link carries.
func (s *Service) ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error) {
	a, err := s.openApproval(ctx, id)
	if err != nil {
		return approval.Request{}, err
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return approval.Request{}, err
	}
	reveal, err := s.deps.Approval.Store.RevealNonce(ctx, approval.KindApprove, id)
	if err != nil {
		return approval.Request{}, err
	}
	return approval.Request{
		ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, RevealNonce: reveal, CredentialIDs: ids,
		Columns: s.columnsOf(ctx, a.Lines),
	}, nil
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (s *Service) RelayApproval(ctx context.Context, r approval.Response) (Receipt, error) {
	if _, err := s.openApproval(ctx, r.ApprovalID); err != nil {
		return Receipt{}, err
	}
	if _, err := s.deps.Approval.Store.SubmitApproval(ctx, r.ApprovalID, r.Assertion()); err != nil {
		return Receipt{}, err
	}
	// Postgres accepted the signature: the receipt names the approval as
	// Postgres records it, never as the page sent it.
	return s.approvalReceipt(ctx, r.ApprovalID)
}

// openApproval is one of this agent's held writes that can still be
// signed.
//
// It admits the call first (Admit): the pages and the MCP tools reach a held write only on a guard this build serves, so no
// signature is relayed to a guard it calls unsafe.
func (s *Service) openApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	if err := s.Admit(ctx); err != nil {
		return action.Approval{}, err
	}
	a, err := s.deps.Approval.Store.FindApproval(ctx, id)
	if sentinel(err, s.deps.Approval.ErrNotFound) {
		return action.Approval{}, ErrNotThisAgent
	}
	if err != nil {
		return action.Approval{}, err
	}
	switch {
	case a.Status == approvalExpired || !s.deps.Core.Now().Before(a.ExpiresAt):
		return a, &toolresult.ToolError{Code: CodeApprovalExpired, Message: fmt.Sprintf("this approval expired at %s; the write stays blocked", a.ExpiresAt.UTC().Format(personTime))}
	case a.Status == approvalApproved:
		return a, approvalInvalid(reasonAlreadyUsed, "this write is already approved; the agent applies it")
	case a.Status == approvalApplied:
		return a, approvalInvalid(reasonAlreadyUsed, "this approval was already used")
	}
	return a, nil
}
