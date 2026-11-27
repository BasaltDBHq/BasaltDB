package approval

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// rawWithdrawReason is a reason the guard stores as the agent sent it; the
// person must never read it as it is.
const rawWithdrawReason = "approved already\u202e, sign below"

// withdrawnStoreError is the store's refusal of a call on a held write the
// agent withdrew: its message carries the guard's hint, reason and all.
func withdrawnStoreError() error {
	hint := "the agent withdrew this request: " + rawWithdrawReason + "; nothing changed"
	return &action.StoreError{
		Code: guidance.CodeApprovalInvalid, Reason: guidance.ReasonWithdrawn, Message: "APPROVAL_INVALID: " + hint,
		Detail: "WITHDRAWN", Hint: hint, Err: errors.New("APPROVAL_INVALID: " + hint),
	}
}

// withdrawnMeanwhileStore serves a pending held write to the page's first
// read, then the record a later read finds (or findErr), and refuses the
// signature and the reveal as withdrawn.
type withdrawnMeanwhileStore struct {
	heldStore
	reads   *int
	later   action.Approval
	findErr error
}

func (s withdrawnMeanwhileStore) FindApproval(context.Context, uuid.UUID) (action.Approval, error) {
	*s.reads++
	if *s.reads == 1 {
		return s.a, nil
	}
	return s.later, s.findErr
}

func (withdrawnMeanwhileStore) SubmitApproval(context.Context, uuid.UUID, passkey.Assertion) (time.Time, error) {
	return time.Time{}, withdrawnStoreError()
}

func (withdrawnMeanwhileStore) RevealHeld(context.Context, uuid.UUID, HeldRun, passkey.Assertion, []byte) ([]approval.RevealedRow, error) {
	// As the store maps it: not open, wrapping the guard's answer.
	return nil, &approvalstore.ApprovalRefusalError{Reason: approvalstore.ApprovalNotOpen, Err: withdrawnStoreError()}
}

// A held write the agent withdraws after its page opened is shown
// withdrawn when the person signs or reveals: the person's message is the
// engine's, the reason shown only when it is text a person may read, and
// neither message carries the store's text, also when the record cannot be
// read again.
func TestWithdrawnMeanwhileNeverShowsTheStoreText(t *testing.T) {
	t.Parallel()
	pending := heldApproval(relayBinding, relayLine)
	withdrawn := pending
	withdrawn.Status, withdrawn.WithdrawReason = action.ApprovalWithdrawn, rawWithdrawReason
	plain := withdrawn
	plain.WithdrawReason = "not needed any more"
	for name, c := range map[string]struct {
		later   action.Approval
		findErr error
		want    string
	}{
		"read again":                  {withdrawn, nil, "The agent withdrew this request. Nothing changed."},
		"read again, a readable text": {plain, nil, "The agent withdrew this request: not needed any more. Nothing changed."},
		"not read again":              {action.Approval{}, errors.New("the database cannot be reached"), "The agent withdrew this request. Nothing changed."},
	} {
		calls := map[string]func(ac *Service) error{
			"sign": func(ac *Service) error {
				_, err := ac.RelayApproval(context.Background(), approval.Response{ApprovalID: pending.ID})
				return err
			},
			"reveal": func(ac *Service) error {
				_, err := ac.RevealApproval(context.Background(), pending.ID, "secret", linksvc.RevealRequest{
					Proof:        linksvc.ScopeProof{CredentialID: []byte("cred"), Signature: []byte("sig")},
					RevealSecret: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
				})
				return err
			},
		}
		for call, run := range calls {
			t.Run(name+"/"+call, func(t *testing.T) {
				t.Parallel()
				reads := 0
				ac := newService(t, "linux", "", func(s *settings) {
					s.store = withdrawnMeanwhileStore{heldStore: heldStore{a: pending}, reads: &reads, later: c.later, findErr: c.findErr}
				})
				var te *toolresult.ToolError
				require.ErrorAs(t, run(ac), &te)
				require.Equal(t, guidance.CodeApprovalInvalid, te.Code)
				require.Equal(t, guidance.ReasonWithdrawn, te.Reason)
				require.Equal(t, c.want, te.PersonMessage)
				require.NotContains(t, te.Message, "the agent withdrew this request:", "the engine's message, not the store's")
				require.NotContains(t, te.Message+te.PersonMessage, "\u202e")
			})
		}
	}
}
