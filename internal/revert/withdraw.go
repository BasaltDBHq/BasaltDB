package revert

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
)

// WithdrawRevert withdraws a revert the agent prepared while it waits for
// the person's signature (CONTRACT.md, Approvals, Withdrawn requests).
// found is false when the agent prepared no revert with that id. The answer
// is the revert as the store records it after the call: WITHDRAWN, or the
// status it kept when it was no longer waiting. The link is never revoked:
// its page shows the revert withdrawn.
func (rc *Service) WithdrawRevert(ctx context.Context, id uuid.UUID, reason string) (action.Withdrawal, bool, error) {
	if _, err := rc.store.Records.FindRevert(ctx, id); err != nil {
		if refusalOf(err).Reason == revertstore.RevertNotFound {
			return action.Withdrawal{}, false, nil
		}
		return action.Withdrawal{}, true, err
	}
	if _, err := rc.store.Undo.WithdrawRevert(ctx, id, reason); err != nil {
		return action.Withdrawal{}, true, err
	}
	r, err := rc.store.Records.FindRevert(ctx, id)
	if err != nil {
		return action.Withdrawal{}, true, err
	}
	status := r.Status
	if status == action.RevertPending && !rc.core.Now().Before(r.ExpiresAt) {
		status = action.RevertExpired
	}
	return action.Withdrawal{Kind: action.WithdrawRevert, ID: r.ID, Status: status, WithdrawnAt: r.WithdrawnAt, Reason: r.WithdrawReason}, true, nil
}
