package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
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
	a, err := s.openApproval(ctx, id, nil)
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
	if _, err := s.openApproval(ctx, r.ApprovalID, nil); err != nil {
		return err
	}
	_, err := s.Approvals.SubmitApproval(ctx, r.ApprovalID, r.Assertion())
	return err
}

// openApproval is one of this agent's held writes that can still be
// signed.
// A non-nil proof must match the binding text (links.ProofMatches),
// checked before anything about the approval is told: a wrong proof is
// answered as an unknown id.
//
// It admits the call first (Admit): the pages, the CLI's link issue and the
// MCP tools reach a held write only on a guard this build serves, so no
// signature is relayed to a guard it calls unsafe.
func (s *Service) openApproval(ctx context.Context, id uuid.UUID, proof *string) (ledger.Approval, error) {
	if err := s.Admit(ctx); err != nil {
		return ledger.Approval{}, err
	}
	a, err := s.Approvals.FindApproval(ctx, id)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return ledger.Approval{}, ErrNotThisAgent
	}
	if err != nil {
		return ledger.Approval{}, err
	}
	if proof != nil && !links.ProofMatches(a.BindingText, *proof) {
		return ledger.Approval{}, ErrNotThisAgent
	}
	switch {
	case a.Status == ledger.ApprovalExpired || !s.Now().Before(a.ExpiresAt):
		return a, &mcp.ToolError{Code: CodeApprovalExpired, Message: fmt.Sprintf("this approval expired at %s; the write stays blocked", a.ExpiresAt.UTC().Format(personTime))}
	case a.Status == ledger.ApprovalApproved:
		return a, approvalInvalid(reasonAlreadyUsed, "this write is already approved; the agent applies it")
	case a.Status == ledger.ApprovalApplied:
		return a, approvalInvalid(reasonAlreadyUsed, "this approval was already used")
	}
	return a, nil
}

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet.
func (s *Service) RevertRequest(ctx context.Context, id uuid.UUID) (revert.Request, error) {
	r, err := s.openRevert(ctx, id, nil)
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
	open, err := s.openRevert(ctx, r.RevertID, nil)
	if err != nil {
		return guard.AppliedRevert{}, err
	}
	applied, err := s.Reverts.ApplyRevert(ctx, r.RevertID, r.Assertion())
	if err != nil {
		return guard.AppliedRevert{}, s.applyRevertError(ctx, open, err)
	}
	return applied, nil
}

// openRevert is a revert this agent's role prepared that can still be
// signed, admitted first as openApproval is.
func (s *Service) openRevert(ctx context.Context, id uuid.UUID, proof *string) (ledger.Revert, error) {
	if err := s.Admit(ctx); err != nil {
		return ledger.Revert{}, err
	}
	r, err := s.Reverts.FindRevert(ctx, id)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return ledger.Revert{}, ErrNotThisAgent
	}
	if err != nil {
		return ledger.Revert{}, err
	}
	if proof != nil && !links.ProofMatches(r.BindingText, *proof) {
		return ledger.Revert{}, ErrNotThisAgent
	}
	switch {
	case r.Status == ledger.RevertExpired || (r.Status == ledger.RevertPending && !s.Now().Before(r.ExpiresAt)):
		return r, s.revertExpired(r)
	case r.Status != ledger.RevertPending:
		return r, alreadySigned(r)
	}
	return r, nil
}

// IssueApprovalLink issues a new short link for one of this agent's held
// writes, revoking its earlier one, to a caller that shows proof of the
// binding text (the CLI; CONTRACT.md, Link secrets).
func (s *Service) IssueApprovalLink(ctx context.Context, id uuid.UUID, proof string) (string, error) {
	a, err := s.openApproval(ctx, id, &proof)
	if err != nil {
		return "", err
	}
	return s.issuedLink(links.Approval, a.ID, a.ExpiresAt)
}

// IssueRevertLink issues a new short link for a revert this agent's role
// prepared, to a caller that shows proof of its binding text.
func (s *Service) IssueRevertLink(ctx context.Context, id uuid.UUID, proof string) (string, error) {
	r, err := s.openRevert(ctx, id, &proof)
	if err != nil {
		return "", err
	}
	return s.issuedLink(links.Revert, r.ID, r.ExpiresAt)
}

// CheckLink reports whether secret is the live link secret of one of this
// agent's items.
func (s *Service) CheckLink(id uuid.UUID, secret string) bool {
	return s.Links.Check(id, secret)
}

// issuedLink is a newly issued short link; this engine must serve the
// pages.
func (s *Service) issuedLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error) {
	link, err := s.localLink(page, id, expires)
	if err != nil {
		return "", err
	}
	if link == "" {
		return "", &mcp.ToolError{Code: CodeUnavailable, Message: "this engine serves no pages"}
	}
	return link, nil
}
