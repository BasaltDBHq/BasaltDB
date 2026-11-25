package revert

import (
	"context"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet, for the page holding
// secret, its live link secret, with the nonce of the next widen read from
// the store. A revert not widened is served from the store. A widened one is
// served from the engine's memory, since the agent role's view shows no
// binding or lines (RS-5): an engine that restarted since asks the person
// to widen again (owner, Q13), with the nonce that widen signs.
func (rc *Service) RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error) {
	release, err := rc.rescopes.lock(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	defer release()
	r, err := rc.openRevert(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	st, held, err := rc.heldState(r, secret)
	if err != nil {
		return revert.Request{}, err
	}
	nonce, err := rc.store.Records.RevertNonce(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	reveal, err := rc.store.Records.RevealNonce(ctx, approval.KindRevert, id)
	if err != nil {
		return revert.Request{}, err
	}
	ids, err := rc.delivery.CredentialIDs(ctx)
	if err != nil {
		return revert.Request{}, err
	}
	switch {
	case r.Widened && held:
		req := st.request
		req.CredentialIDs, req.RescopeNonce, req.RevealNonce = ids, nonce, reveal
		req.Columns = rc.delivery.ColumnsOf(ctx, req.Lines)
		return req, nil
	case r.Widened:
		return revert.Request{}, widenAgain(nonce)
	}
	return revert.Request{
		RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, RescopeNonce: nonce, RevealNonce: reveal, CredentialIDs: ids,
		Columns: rc.delivery.ColumnsOf(ctx, r.Lines),
	}, nil
}

// RelayRevert applies the person's signed revert (apply_revert): the store
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
func (rc *Service) RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, linksvc.Receipt, error) {
	open, err := rc.openRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, linksvc.Receipt{}, err
	}
	applied, err := rc.store.Proofs.ApplyRevert(ctx, r.RevertID, r.Assertion())
	if err != nil {
		return action.AppliedRevert{}, linksvc.Receipt{}, rc.applyRevertError(ctx, open, err)
	}
	// The store accepted the signature: the receipt names the revert as
	// the store records it now.
	signed, err := rc.store.Records.FindRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, linksvc.Receipt{}, err
	}
	receipt, err := rc.revertReceipt(signed)
	if err != nil {
		return action.AppliedRevert{}, linksvc.Receipt{}, err
	}
	return applied, receipt, nil
}

// openRevert is a revert this agent's role prepared that can still be
// signed, admitted first as openApproval is.
func (rc *Service) openRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	if err := rc.admit.Admit(ctx); err != nil {
		return action.Revert{}, err
	}
	r, err := rc.store.Records.FindRevert(ctx, id)
	if refusalOf(err).Reason == action.RevertNotFound {
		return action.Revert{}, linksvc.ErrNotThisAgent
	}
	if err != nil {
		return action.Revert{}, err
	}
	switch {
	case r.Status == action.RevertExpired || (r.Status == action.RevertPending && !rc.core.Now().Before(r.ExpiresAt)):
		return r, rc.revertExpired(r)
	case r.Status != action.RevertPending:
		return r, alreadySigned(r)
	}
	return r, nil
}
