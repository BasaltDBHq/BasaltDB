package approval

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// revealStore serves one held write and records the one reveal call it
// gets, which it refuses as the store refuses a proof.
type revealStore struct {
	heldStore
	calls *[]revealCall
}

type revealCall struct {
	id    uuid.UUID
	held  HeldRun
	proof passkey.Assertion
	key   []byte
}

func (s revealStore) RevealHeld(_ context.Context, id uuid.UUID, held HeldRun, proof passkey.Assertion, key []byte) ([]approval.RevealedRow, error) {
	*s.calls = append(*s.calls, revealCall{id: id, held: held, proof: proof, key: append([]byte(nil), key...)})
	return nil, refused(action.ApprovalRevealRefused)
}

// The service reads only the binding's shared part and hands the store the
// held request as the binding carries it, unread, in one call with the
// person's proof and reveal key.
func TestRevealApprovalHandsTheStoreTheHeldRequestUnread(t *testing.T) {
	t.Parallel()
	const filter = `{\"status\": \"spam\", \"id\": {\"$in\": [3]}}`
	binding := strings.Replace(relayBinding, `"statement": "DELETE FROM public.leads WHERE id = $1"`, `"statement": "`+filter+`"`, 1)
	binding = strings.Replace(binding, `"taskId": null`, `"taskId": "0193a4c2-7d1e-7c3a-9f00-0000000000c3"`, 1)
	a := heldApproval(binding, relayLine)
	b, err := approval.ParseBinding(binding)
	require.NoError(t, err)
	require.Equal(t, `{"status": "spam", "id": {"$in": [3]}}`, b.Request.Statement, "a request that is not SQL")

	var calls []revealCall
	ac := newService(t, "linux", "", func(s *settings) { s.store = revealStore{heldStore: heldStore{a: a}, calls: &calls} })
	in := linksvc.RevealRequest{
		Proof:        linksvc.ScopeProof{CredentialID: []byte("cred"), Signature: []byte("sig")},
		RevealSecret: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	_, err = ac.RevealApproval(context.Background(), a.ID, "secret", in)

	var pe *guidance.PageError
	require.ErrorAs(t, err, &pe, "the store's refusal is the page's answer")
	require.Equal(t, guardmodel.RevealRefused, pe.Reason)
	require.Len(t, calls, 1, "one store call")
	got := calls[0]
	require.Equal(t, a.ID, got.id)
	require.Equal(t, action.Intent{
		RunID:  uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000b2"),
		TaskID: uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000c3"),
		Text:   "Remove the spam lead",
	}, got.held.Intent)
	require.Equal(t, b.Request, got.held.Request, "the binding's request, as signed")
	require.Equal(t, in.Proof.Assertion(), got.proof)
	key, err := in.RevealKey()
	require.NoError(t, err)
	require.Equal(t, key, got.key)
}

// A binding that does not parse never reaches the store.
func TestRevealApprovalRefusesABindingThatDoesNotParse(t *testing.T) {
	t.Parallel()
	a := heldApproval(strings.Replace(relayBinding, `"kind": "APPROVE"`, `"kind": "REVERT"`, 1), relayLine)
	var calls []revealCall
	ac := newService(t, "linux", "", func(s *settings) { s.store = revealStore{heldStore: heldStore{a: a}, calls: &calls} })
	in := linksvc.RevealRequest{RevealSecret: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	_, err := ac.RevealApproval(context.Background(), a.ID, "secret", in)
	require.Error(t, err)
	require.Empty(t, calls)
}
