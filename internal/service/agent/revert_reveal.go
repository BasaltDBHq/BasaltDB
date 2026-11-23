package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// RevealRevert reveals the hidden rows of a revert this agent's role
// prepared to the person on the revert page holding secret, its live link
// secret. It serializes with the revert's other page routes; Postgres
// locks the revert row, so a signature racing it comes first or second,
// never between.
func (rc *revertCase) RevealRevert(ctx context.Context, id uuid.UUID, secret string, in RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.revealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	release, err := rc.rescopes.lock(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer release()
	r, err := rc.openRevert(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	st, held, err := rc.heldState(r, secret)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	lines := r.Lines
	if r.Widened {
		if !held {
			nonce, err := rc.deps.Store.RevertNonce(ctx, id)
			if err != nil {
				return approval.RevealAnswer{}, err
			}
			return approval.RevealAnswer{}, widenAgain(nonce)
		}
		lines = st.request.Lines
	}
	out, err := rc.deps.Store.RevealRevertRows(ctx, id, in.Proof.assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, rc.revealRevertError(r, err, rc.delivery.PageLink(links.Revert, id, secret))
	}
	if out.RowsChanged {
		return approval.RevealAnswer{}, RevealRowsChanged(guidance.CodeRevertInvalid, "revert", "Prepare it again")
	}
	return CheckedAnswer(lines, out.Rows)
}

// revealRevertError is the page's answer to a revert reveal Postgres
// refused.
func (rc *revertCase) revealRevertError(r action.Revert, err error, link string) error {
	code, _ := guidance.LedgerCode(err)
	detail := guidance.StoreDetail(err)
	switch {
	case code == guardmodel.CodeRevertInvalid && detail == guardmodel.RevealRefused:
		return RevealRefused(guidance.CodeRevertInvalid, link)
	case code == guardmodel.CodeRevertInvalid && detail == revertNotFoundDetail:
		return ErrNotThisAgent
	case code == guardmodel.CodeRevertExpired:
		return rc.revertExpired(r)
	case code == guardmodel.CodeRevertInvalid:
		return &guidance.PageError{ToolError: &toolresult.ToolError{
			Code:          guidance.CodeRevertInvalid,
			Message:       "the hidden rows cannot be shown: the revert was signed or rejected meanwhile",
			PersonMessage: "This revert was signed or rejected meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}
