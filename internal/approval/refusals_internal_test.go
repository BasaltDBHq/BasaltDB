package approval

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// errStore is the store's own error a refusal wraps in these tests.
var errStore = errors.New("the store's own text")

func refused(reason approvalstore.ApprovalReason) error {
	return &approvalstore.ApprovalRefusalError{Reason: reason, Err: errStore}
}

// missingStore holds no approval: the store refuses every find NOT_FOUND.
type missingStore struct{ catalogStore }

func (missingStore) FindApproval(context.Context, uuid.UUID) (action.Approval, error) {
	return action.Approval{}, refused(approvalstore.ApprovalNotFound)
}

// An approval the store does not find is the page's ErrNotThisAgent, for
// the page's request and for the person's signed approval.
func TestOpenApprovalNotFoundIsNotThisAgent(t *testing.T) {
	t.Parallel()
	ac := newService(t, "linux", "", func(s *settings) { s.store = missingStore{} })
	id := uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1")
	_, err := ac.ApprovalRequest(context.Background(), id)
	require.ErrorIs(t, err, linksvc.ErrNotThisAgent)
	_, err = ac.openApproval(context.Background(), id)
	require.ErrorIs(t, err, linksvc.ErrNotThisAgent)
}

// Each reveal refusal gives the page today's answer; any other error
// passes through as it is.
func TestRevealApprovalErrorByReason(t *testing.T) {
	t.Parallel()
	const link = "http://localhost:8787/approvals/0193a4c2-7d1e-7c3a-9f00-0000000000a1#s=AAEC"
	ac := &Service{}
	pageError := func(t *testing.T, err error) *guidance.PageError {
		t.Helper()
		var pe *guidance.PageError
		require.ErrorAs(t, err, &pe)
		return pe
	}

	t.Run("reveal refused", func(t *testing.T) {
		t.Parallel()
		pe := pageError(t, ac.revealApprovalError(context.Background(), uuid.Nil, refused(approvalstore.ApprovalRevealRefused), link))
		require.Equal(t, guidance.CodeApprovalInvalid, pe.Code)
		require.Equal(t, guidance.ReasonRevealRefused, pe.Reason)
	})
	t.Run("rows changed", func(t *testing.T) {
		t.Parallel()
		pe := pageError(t, ac.revealApprovalError(context.Background(), uuid.Nil, refused(approvalstore.ApprovalRevealRowsChanged), link))
		require.Equal(t, guidance.CodeApprovalInvalid, pe.Code)
		require.Equal(t, guidance.ReasonRowsChanged, pe.Reason)
	})
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, ac.revealApprovalError(context.Background(), uuid.Nil, refused(approvalstore.ApprovalNotFound), link), linksvc.ErrNotThisAgent)
	})
	t.Run("not open", func(t *testing.T) {
		t.Parallel()
		pe := pageError(t, ac.revealApprovalError(context.Background(), uuid.Nil, refused(approvalstore.ApprovalNotOpen), link))
		require.Equal(t, guidance.CodeApprovalInvalid, pe.Code)
		require.Equal(t, "the hidden rows cannot be shown: the approval was signed or used meanwhile", pe.Message)
	})
	t.Run("other error", func(t *testing.T) {
		t.Parallel()
		require.Same(t, errStore, ac.revealApprovalError(context.Background(), uuid.Nil, errStore, link))
	})
}
