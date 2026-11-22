package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// What the engine's local pages ask of an agent (CONTRACT.md, Local
// pages): the request a short link stands for, and the relay of the
// person's signature with this agent's credential. The relay decides
// nothing: Postgres verifies the passkey signature.

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
	reveal, err := s.Store.RevealNonce(ctx, approval.KindApprove, id)
	if err != nil {
		return approval.Request{}, err
	}
	return approval.Request{
		ApprovalID: a.ID, Binding: a.BindingText, Lines: a.Lines, RevealNonce: reveal, CredentialIDs: ids,
		Columns: s.columnsOf(ctx, a.Lines),
	}, nil
}

// ColumnOrder reads tables' columns in table order (attnum).
type ColumnOrder interface {
	// ColumnOrder maps each table name, as the lines spell it, to its
	// columns; a table it cannot find is left out.
	ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error)
}

// columnsOf is the column order of the tables lines name, for the pages'
// display only (CONTRACT.md, Local pages): never signed, and a failure
// only costs the order, so it is logged and nil is returned.
func (s *Service) columnsOf(ctx context.Context, lines []string) approval.ColumnOrder {
	if s.Columns == nil {
		return nil
	}
	seen := map[string]bool{}
	var tables []string
	for _, l := range lines {
		var line struct {
			Table string `json:"table"`
		}
		if json.Unmarshal([]byte(l), &line) != nil || line.Table == "" || seen[line.Table] {
			continue
		}
		seen[line.Table] = true
		tables = append(tables, line.Table)
	}
	if len(tables) == 0 {
		return nil
	}
	cols, err := s.Columns.ColumnOrder(ctx, tables)
	if err != nil {
		s.Log.WarnContext(ctx, "pages: column order not read; the page shows the rows' order", "err", err)
		return nil
	}
	if len(cols) == 0 {
		return nil
	}
	return cols
}

// RelayApproval submits the person's signed approval of one of this
// agent's held writes (submit_approval).
func (s *Service) RelayApproval(ctx context.Context, r approval.Response) (Receipt, error) {
	if _, err := s.openApproval(ctx, r.ApprovalID); err != nil {
		return Receipt{}, err
	}
	if _, err := s.Store.SubmitApproval(ctx, r.ApprovalID, r.Assertion()); err != nil {
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
func (s *Service) openApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	if err := s.Admit(ctx); err != nil {
		return ledger.Approval{}, err
	}
	a, err := s.Store.FindApproval(ctx, id)
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
		return a, approvalInvalid(reasonAlreadyUsed, "this write is already approved; the agent applies it")
	case a.Status == ledger.ApprovalApplied:
		return a, approvalInvalid(reasonAlreadyUsed, "this approval was already used")
	}
	return a, nil
}

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet, for the page holding
// secret, its live link secret, with the nonce of the next widen read from
// Postgres. A revert not widened is served from Postgres. A widened one is
// served from the engine's memory, since the agent role's view shows no
// binding or lines (RS-5): an engine that restarted since asks the person
// to widen again (owner, Q13), with the nonce that widen signs.
func (s *Service) RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error) {
	release, err := s.rescopes.lock(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	defer release()
	r, err := s.openRevert(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	st, held, err := s.heldState(r, secret)
	if err != nil {
		return revert.Request{}, err
	}
	nonce, err := s.Store.RevertNonce(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	reveal, err := s.Store.RevealNonce(ctx, approval.KindRevert, id)
	if err != nil {
		return revert.Request{}, err
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return revert.Request{}, err
	}
	switch {
	case r.Widened && held:
		req := st.request
		req.CredentialIDs, req.RescopeNonce, req.RevealNonce = ids, nonce, reveal
		req.Columns = s.columnsOf(ctx, req.Lines)
		return req, nil
	case r.Widened:
		return revert.Request{}, widenAgain(nonce)
	}
	return revert.Request{
		RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, RescopeNonce: nonce, RevealNonce: reveal, CredentialIDs: ids,
		Columns: s.columnsOf(ctx, r.Lines),
	}, nil
}

// RelayRevert applies the person's signed revert (apply_revert): Postgres
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
func (s *Service) RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, Receipt, error) {
	open, err := s.openRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	applied, err := s.Store.ApplyRevert(ctx, r.RevertID, r.Assertion())
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, s.applyRevertError(ctx, open, err)
	}
	// Postgres accepted the signature: the receipt names the revert as
	// Postgres records it now.
	signed, err := s.Store.FindRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	receipt, err := s.revertReceipt(signed)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	return applied, receipt, nil
}

// openRevert is a revert this agent's role prepared that can still be
// signed, admitted first as openApproval is.
func (s *Service) openRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	if err := s.Admit(ctx); err != nil {
		return ledger.Revert{}, err
	}
	r, err := s.Store.FindRevert(ctx, id)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return ledger.Revert{}, ErrNotThisAgent
	}
	if err != nil {
		return ledger.Revert{}, err
	}
	switch {
	case r.Status == ledger.RevertExpired || (r.Status == ledger.RevertPending && !s.Now().Before(r.ExpiresAt)):
		return r, s.revertExpired(r)
	case r.Status != ledger.RevertPending:
		return r, alreadySigned(r)
	}
	return r, nil
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
