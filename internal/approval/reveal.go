package approval

import (
	"context"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// RevealApproval reveals the hidden rows of one of this agent's held
// writes to the person on the approval page: the store checks the person's
// proof, re-runs the held write in a preview that rolls back, recorded as
// an apply records it, and reads the rows there, for the page holding
// secret, the approval's live link secret. The service reads only the
// binding's shared part and passes its request to the store unread.
func (ac *Service) RevealApproval(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.RevealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	a, err := ac.openApproval(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	held, err := heldWrite(a)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	rows, err := ac.store.Proofs.RevealHeld(ctx, id, held, in.Proof.Assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, ac.revealApprovalError(ctx, id, err, ac.delivery.PageLink(links.Approval, id, secret))
	}
	return linksvc.CheckedAnswer(a.Lines, rows)
}

// HeldRun is what re-runs a held write (approvalstore.HeldRun).
type HeldRun = approvalstore.HeldRun

// heldWrite reads the held write from approval a's binding.
func heldWrite(a action.Approval) (HeldRun, error) {
	b, err := approval.ParseBinding(a.BindingText)
	if err != nil {
		return HeldRun{}, err
	}
	in := action.Intent{RunID: b.RunID, Text: b.Intent}
	if b.TaskID != nil {
		in.TaskID = *b.TaskID
	}
	return HeldRun{Intent: in, Request: b.Request}, nil
}

// revealApprovalError is the page's answer to a reveal the store refused,
// by the store's refusal reason. A held write withdrawn after the page
// opened is shown withdrawn (withdrawnMeanwhile).
func (ac *Service) revealApprovalError(ctx context.Context, id uuid.UUID, err error, link string) error {
	if ac.core.Errors.ToolError(err).Reason == guidance.ReasonWithdrawn {
		return ac.withdrawnMeanwhile(ctx, id, err)
	}
	ar := approvalstore.ApprovalRefusalOf(err)
	if ar == nil {
		return err
	}
	switch ar.Reason {
	case approvalstore.ApprovalRevealRefused:
		return linksvc.RevealRefused(guidance.CodeApprovalInvalid, link)
	case approvalstore.ApprovalRevealRowsChanged:
		return linksvc.RevealRowsChanged(guidance.CodeApprovalInvalid, "approval", "This approval can no longer apply; ask the agent to try the write again")
	case approvalstore.ApprovalNotFound:
		return linksvc.ErrNotThisAgent
	case approvalstore.ApprovalNotOpen:
		return &guidance.PageError{ToolError: &toolresult.ToolError{
			Code:          guidance.CodeApprovalInvalid,
			Message:       "the hidden rows cannot be shown: the approval was signed or used meanwhile",
			PersonMessage: "This approval was signed or used meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}
