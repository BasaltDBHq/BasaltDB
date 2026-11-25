package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

// heldStore serves one pending held write.
type heldStore struct {
	catalogStore
	a action.Approval
}

func (s heldStore) FindApproval(context.Context, uuid.UUID) (action.Approval, error) { return s.a, nil }

func (heldStore) RevealNonce(context.Context, string, uuid.UUID) ([]byte, error) {
	return []byte("reveal nonce"), nil
}

const (
	relayBinding = `{"kind": "APPROVE", "rows": 1, "agent": "agent:bot", "runId": "0193a4c2-7d1e-7c3a-9f00-0000000000b2", "store": {"kind": "POSTGRES", "name": "app"}, ` +
		`"intent": "Remove the spam lead", "taskId": null, "request": {"kind": "SQL", "params": [3], "statement": "DELETE FROM public.leads WHERE id = $1"}, ` +
		`"rowsHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80", "expiresAt": "2026-11-12T06:02:11.123456Z", ` +
		`"approvalId": "0193a4c2-7d1e-7c3a-9f00-0000000000a1", "assignedFields": []}`
	relayLine = `{"op": "DELETE", "key": {"id": 3}, "old": {"id": 3, "status": "open"}, "set": null, "shape": "RECORD", "store": {"kind": "POSTGRES", "verb": "DELETE"}, "cascaded": false, "resource": "public.leads"}`
)

func heldApproval(binding, line string) action.Approval {
	return action.Approval{
		ID: uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1"), Status: action.ApprovalPending,
		ExpiresAt: time.Now().Add(time.Hour), BindingText: binding, Lines: []string{line},
	}
}

// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): the approval page's request refuses a binding or a
// line from the store that breaks them.
func TestApprovalRequestRefusesTextsOutOfTheRules(t *testing.T) {
	t.Parallel()
	ok := heldApproval(relayBinding, relayLine)
	ac := newService(t, "linux", "", func(s *settings) { s.store = heldStore{a: ok} })
	_, err := ac.ApprovalRequest(context.Background(), ok.ID)
	require.NoError(t, err, "texts in the rules are relayed")

	for name, a := range map[string]action.Approval{
		"binding": heldApproval(strings.Replace(relayBinding, `"rows": 1, `, `"rows":1, `, 1), relayLine),
		"line":    heldApproval(relayBinding, strings.Replace(relayLine, `"cascaded": false`, `"cascaded":false`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ac := newService(t, "linux", "", func(s *settings) { s.store = heldStore{a: a} })
			_, err := ac.ApprovalRequest(context.Background(), a.ID)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
		})
	}
}
