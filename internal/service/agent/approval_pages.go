package agent

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalRequest is the approval request of a held write still waiting
// for the person's signature: the JSON the long link carries.
func (ac *approvalCase) ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error) {
	a, err := ac.openApproval(ctx, id)
	if err != nil {
		return approval.Request{}, err
	}
	ids, err := ac.delivery.credentialIDs(ctx)
	if err != nil {
		return approval.Request{}, err
	}
	reveal, err := ac.deps.Store.RevealNonce(ctx, approval.KindApprove, id)
	if err != nil {
		return approval.Request{}, err
	}
	return approval.Request{
		ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, RevealNonce: reveal, CredentialIDs: ids,
		Columns: ac.delivery.columnsOf(ctx, a.Lines),
	}, nil
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (ac *approvalCase) RelayApproval(ctx context.Context, r approval.Response) (Receipt, error) {
	if _, err := ac.openApproval(ctx, r.ApprovalID); err != nil {
		return Receipt{}, err
	}
	if _, err := ac.deps.Store.SubmitApproval(ctx, r.ApprovalID, r.Assertion()); err != nil {
		return Receipt{}, err
	}
	// Postgres accepted the signature: the receipt names the approval as
	// Postgres records it, never as the page sent it.
	return ac.delivery.approvalReceipt(ctx, r.ApprovalID)
}

// openApproval is one of this agent's held writes that can still be
// signed.
//
// It admits the call first (Admit): the pages and the MCP tools reach a held write only on a guard this build serves, so no
// signature is relayed to a guard it calls unsafe.
func (ac *approvalCase) openApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	if err := ac.admit.Admit(ctx); err != nil {
		return action.Approval{}, err
	}
	a, err := ac.deps.Store.FindApproval(ctx, id)
	if guidance.Sentinel(err, ac.deps.ErrNotFound) {
		return action.Approval{}, ErrNotThisAgent
	}
	if err != nil {
		return action.Approval{}, err
	}
	switch {
	case a.Status == approvalExpired || !ac.core.Now().Before(a.ExpiresAt):
		return a, &toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: fmt.Sprintf("this approval expired at %s; the write stays blocked", a.ExpiresAt.UTC().Format(guidance.PersonTime))}
	case a.Status == approvalApproved:
		return a, approvalInvalid(guidance.ReasonAlreadyUsed, "this write is already approved; the agent applies it")
	case a.Status == approvalApplied:
		return a, approvalInvalid(guidance.ReasonAlreadyUsed, "this approval was already used")
	}
	return a, nil
}
