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
func (rc *revertCase) RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error) {
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
	nonce, err := rc.deps.Store.RevertNonce(ctx, id)
	if err != nil {
		return revert.Request{}, err
	}
	reveal, err := rc.deps.Store.RevealNonce(ctx, approval.KindRevert, id)
	if err != nil {
		return revert.Request{}, err
	}
	ids, err := rc.delivery.credentialIDs(ctx)
	if err != nil {
		return revert.Request{}, err
	}
	switch {
	case r.Widened && held:
		req := st.request
		req.CredentialIDs, req.RescopeNonce, req.RevealNonce = ids, nonce, reveal
		req.Columns = rc.delivery.columnsOf(ctx, req.Lines)
		return req, nil
	case r.Widened:
		return revert.Request{}, widenAgain(nonce)
	}
	return revert.Request{
		RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, RescopeNonce: nonce, RevealNonce: reveal, CredentialIDs: ids,
		Columns: rc.delivery.columnsOf(ctx, r.Lines),
	}, nil
}

// RelayRevert applies the person's signed revert (apply_revert): Postgres
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
func (rc *revertCase) RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, Receipt, error) {
	open, err := rc.openRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	applied, err := rc.deps.Store.ApplyRevert(ctx, r.RevertID, r.Assertion())
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, rc.applyRevertError(ctx, open, err)
	}
	// Postgres accepted the signature: the receipt names the revert as
	// Postgres records it now.
	signed, err := rc.deps.Store.FindRevert(ctx, r.RevertID)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	receipt, err := rc.revertReceipt(signed)
	if err != nil {
		return action.AppliedRevert{}, Receipt{}, err
	}
	return applied, receipt, nil
}

// openRevert is a revert this agent's role prepared that can still be
// signed, admitted first as openApproval is.
func (rc *revertCase) openRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	if err := rc.admit.Admit(ctx); err != nil {
		return action.Revert{}, err
	}
	r, err := rc.deps.Store.FindRevert(ctx, id)
	if guidance.Sentinel(err, rc.deps.ErrNotFound) {
		return action.Revert{}, ErrNotThisAgent
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
