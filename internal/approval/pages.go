package approval

import (
	"context"
	"fmt"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalRequest is the approval request of a held write still waiting
// for the person's signature: the JSON the long link carries.
func (ac *Service) ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error) {
	a, err := ac.openApproval(ctx, id)
	if err != nil {
		return approval.Request{}, err
	}
	// The engine relays only texts that follow the text rules.
	if err := approval.CheckTexts(a.BindingText, a.Lines...); err != nil {
		return approval.Request{}, err
	}
	ids, err := ac.delivery.CredentialIDs(ctx)
	if err != nil {
		return approval.Request{}, err
	}
	reveal, err := ac.store.Records.RevealNonce(ctx, approval.KindApprove, id)
	if err != nil {
		return approval.Request{}, err
	}
	return approval.Request{
		ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, RevealNonce: reveal, CredentialIDs: ids,
		Fields: ac.delivery.FieldsOf(ctx, a.Lines),
	}, nil
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (ac *Service) RelayApproval(ctx context.Context, r approval.Response) (linksvc.Receipt, error) {
	if _, err := ac.openApproval(ctx, r.ApprovalID); err != nil {
		return linksvc.Receipt{}, err
	}
	if _, err := ac.store.Proofs.SubmitApproval(ctx, r.ApprovalID, r.Assertion()); err != nil {
		return linksvc.Receipt{}, ac.withdrawnMeanwhile(ctx, r.ApprovalID, err)
	}
	// The store accepted the signature: the receipt names the approval as
	// the store records it, never as the page sent it.
	return ac.delivery.ApprovalReceipt(ctx, r.ApprovalID)
}

// openApproval is one of this agent's held writes that can still be
// signed.
//
// It admits the call first (Admit): the pages and the MCP tools reach a held write only on a guard this build serves, so no
// signature is relayed to a guard it calls unsafe.
func (ac *Service) openApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	if err := ac.admit.Admit(ctx); err != nil {
		return action.Approval{}, err
	}
	a, err := ac.store.Records.FindApproval(ctx, id)
	if approvalstore.IsApprovalRefused(err, approvalstore.ApprovalNotFound) {
		return action.Approval{}, linksvc.ErrNotThisAgent
	}
	if err != nil {
		return action.Approval{}, err
	}
	switch {
	case a.Status == action.ApprovalWithdrawn:
		return a, Withdrawn(a)
	case a.Status == action.ApprovalExpired || !ac.core.Now().Before(a.ExpiresAt):
		return a, &toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: fmt.Sprintf("this approval expired at %s; the write stays blocked", a.ExpiresAt.UTC().Format(guidance.PersonTime))}
	case a.Status == action.ApprovalApproved:
		return a, ApprovalInvalid(guidance.ReasonAlreadyUsed, "this write is already approved; the agent applies it")
	case a.Status == action.ApprovalApplied:
		return a, ApprovalInvalid(guidance.ReasonAlreadyUsed, "this approval was already used")
	}
	return a, nil
}

// withdrawnMeanwhile is the answer when the store refused a signature
// because the agent withdrew the held write after the page opened: the
// page shows it withdrawn, with the agent's reason. Any other refusal is
// err as it is.
func (ac *Service) withdrawnMeanwhile(ctx context.Context, id uuid.UUID, err error) error {
	if ac.core.Errors.ToolError(err).Reason != guidance.ReasonWithdrawn {
		return err
	}
	a, findErr := ac.store.Records.FindApproval(ctx, id)
	if findErr != nil {
		return err
	}
	return Withdrawn(a)
}
