package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

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
	nonce, err := s.deps.Revert.Store.RevertNonce(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	reveal, err := s.deps.Revert.Store.RevealNonce(ctx, approval.KindRevert, id)
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
	applied, err := s.deps.Revert.Store.ApplyRevert(ctx, r.RevertID, r.Assertion())
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, s.applyRevertError(ctx, open, err)
	}
	// Postgres accepted the signature: the receipt names the revert as
	// Postgres records it now.
	signed, err := s.deps.Revert.Store.FindRevert(ctx, r.RevertID)
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
func (s *Service) openRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	if err := s.Admit(ctx); err != nil {
		return action.Revert{}, err
	}
	r, err := s.deps.Revert.Store.FindRevert(ctx, id)
	if guidance.Sentinel(err, s.deps.Revert.ErrNotFound) {
		return action.Revert{}, ErrNotThisAgent
	}
	if err != nil {
		return action.Revert{}, err
	}
	switch {
	case r.Status == revertExpired || (r.Status == revertPending && !s.deps.Core.Now().Before(r.ExpiresAt)):
		return r, s.revertExpired(r)
	case r.Status != revertPending:
		return r, alreadySigned(r)
	}
	return r, nil
}
