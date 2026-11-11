package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// What the engine's local pages ask of an agent (CONTRACT.md, Local
// pages): the request a short link stands for, and the relay of the
// person's signature with this agent's credential, as basalt approve and
// basalt revert do. The relay decides nothing: Postgres verifies the
// passkey signature.

// ErrNotThisAgent is an approval or revert this agent's role cannot see:
// another agent's, or none.
var ErrNotThisAgent = errors.New("not one of this agent's approvals or reverts")

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
	return approval.Request{ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, CredentialIDs: ids}, nil
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (s *Service) RelayApproval(ctx context.Context, r approval.Response) error {
	if _, err := s.openApproval(ctx, r.ApprovalID); err != nil {
		return err
	}
	_, err := s.Approvals.SubmitApproval(ctx, r.ApprovalID, r.Assertion())
	return err
}

// openApproval is one of this agent's held writes that can still be
// signed.
func (s *Service) openApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	a, err := s.Approvals.FindApproval(ctx, id)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return ledger.Approval{}, ErrNotThisAgent
	}
	if err != nil {
		return ledger.Approval{}, err
	}
	switch {
	case a.Status == ledger.ApprovalExpired || !s.Now().Before(a.ExpiresAt):
		return a, &mcp.ToolError{Code: CodeApprovalExpired, Message: fmt.Sprintf("this approval expired at %s; the write stays blocked", a.ExpiresAt.UTC().Format(personTime))}
	case a.Status == ledger.ApprovalApproved:
		return a, approvalInvalid("this write is already approved; the agent applies it")
	case a.Status == ledger.ApprovalApplied:
		return a, approvalInvalid("this approval was already used")
	}
	return a, nil
}

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet.
func (s *Service) RevertRequest(ctx context.Context, id uuid.UUID) (revert.Request, error) {
	r, err := s.openRevert(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return revert.Request{}, err
	}
	return revert.Request{RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, CredentialIDs: ids}, nil
}

// RelayRevert applies the person's signed revert (apply_revert): Postgres
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
func (s *Service) RelayRevert(ctx context.Context, r revert.Response) (guard.AppliedRevert, error) {
	if _, err := s.openRevert(ctx, r.RevertID); err != nil {
		return guard.AppliedRevert{}, err
	}
	return s.Reverts.ApplyRevert(ctx, r.RevertID, r.Assertion())
}

func (s *Service) openRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	r, err := s.Reverts.FindRevert(ctx, id)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return ledger.Revert{}, ErrNotThisAgent
	}
	if err != nil {
		return ledger.Revert{}, err
	}
	switch {
	case r.Status == ledger.RevertExpired || (r.Status == ledger.RevertPending && !s.Now().Before(r.ExpiresAt)):
		return r, &mcp.ToolError{Code: string(guard.CodeRevertExpired), Message: "this revert expired; nothing was reverted. Run basalt revert again."}
	case r.Status != ledger.RevertPending:
		return r, &mcp.ToolError{Code: string(guard.CodeRevertInvalid), Message: "this revert is already signed"}
	}
	return r, nil
}
