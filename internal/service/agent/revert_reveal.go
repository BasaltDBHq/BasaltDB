package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// RevealRevert reveals the hidden rows of a revert this agent's role
// prepared to the person on the revert page holding secret, its live link
// secret. It serializes with the revert's other page routes; Postgres
// locks the revert row, so a signature racing it comes first or second,
// never between.
func (s *Service) RevealRevert(ctx context.Context, id uuid.UUID, secret string, in RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.revealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	release, err := s.rescopes.lock(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer release()
	r, err := s.openRevert(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	st, held, err := s.heldState(r, secret)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	lines := r.Lines
	if r.Widened {
		if !held {
			nonce, err := s.deps.Revert.Store.RevertNonce(ctx, id)
			if err != nil {
				return approval.RevealAnswer{}, err
			}
			return approval.RevealAnswer{}, widenAgain(nonce)
		}
		lines = st.request.Lines
	}
	out, err := s.deps.Revert.Store.RevealRevertRows(ctx, id, in.Proof.assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, s.revealRevertError(r, err, s.pageLink(links.Revert, id, secret))
	}
	if out.RowsChanged {
		return approval.RevealAnswer{}, revealRowsChanged(CodeRevertInvalid, "revert", "Prepare it again")
	}
	return checkedAnswer(lines, out.Rows)
}

// revealRevertError is the page's answer to a revert reveal Postgres
// refused.
func (s *Service) revealRevertError(r action.Revert, err error, link string) error {
	code, _ := ledgerCode(err)
	detail := storeDetail(err)
	switch {
	case code == guardmodel.CodeRevertInvalid && detail == guardmodel.RevealRefused:
		return revealRefused(CodeRevertInvalid, link)
	case code == guardmodel.CodeRevertInvalid && detail == revertNotFoundDetail:
		return ErrNotThisAgent
	case code == guardmodel.CodeRevertExpired:
		return s.revertExpired(r)
	case code == guardmodel.CodeRevertInvalid:
		return &PageError{ToolError: &toolresult.ToolError{
			Code:          CodeRevertInvalid,
			Message:       "the hidden rows cannot be shown: the revert was signed or rejected meanwhile",
			PersonMessage: "This revert was signed or rejected meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}
