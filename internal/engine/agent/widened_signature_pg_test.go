package agent_test

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// widenedSentence is what every wait-form answer for a widened revert
// tells the person (CONTRACT.md, request_revert, Wait form).
const widenedSentence = "You changed the scope on the signing page; the agent cannot see what you added."

// widen has the person widen bot's task revert to every agent on the page.
// It returns the binding of bot's proposal, as the agent's link read it
// before, and the widened binding the person signs.
func (e *rescopeEnv) widen(t *testing.T, id uuid.UUID, agentSecret string) (own, wide string) {
	t.Helper()
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), agentSecret, &read))
	var widened scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret,
		e.widenBody(t, e.person, id, e.nonce(t, id, agentSecret), e.every(), newLinkSecret(t)), &widened))
	b, err := widened.Request.Check()
	require.NoError(t, err)
	require.True(t, b.Widened)
	return read.Binding, widened.Request.Binding
}

// requireWidenedAnswer checks a wait-form answer for a widened revert:
// widened, status and totals, and nothing of the scope or a link.
func requireWidenedAnswer(t *testing.T, body map[string]any, status string) {
	t.Helper()
	require.Equal(t, status, body["status"], "%v", body)
	require.Equal(t, true, body["widened"], "%v", body)
	for _, key := range []string{"scope", "scopeId", "select", "revertUrl", "links"} {
		require.NotContains(t, body, key)
	}
	require.Contains(t, str(t, body["personMessage"]), widenedSentence)
}

// requireNoLink checks that no step of an answer for a widened revert
// carries a link: the agent holds none to the person's scope.
func requireNoLink(t *testing.T, steps []map[string]any) {
	t.Helper()
	for _, s := range steps {
		require.NotContains(t, s, "url", "%v", s)
	}
}

// The person widens bot's task revert on the page, signs it, and gives the
// code to the agent. The agent role cannot read the widened binding, so
// the engine leaves the signature to apply_revert, which applies every
// agent's rows. The wait form shows the agent status and totals only.
func TestRequestRevertDeliversAWidenedRevertsSignature(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	_, binding := e.widen(t, id, agentSecret)

	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "waitForSignature": 0})
	require.False(t, isError, "%v", body)
	requireWidenedAnswer(t, body, "PENDING")
	requireNoLink(t, requireResultSteps(t, body, "WAIT_ENDED"))

	code := revertCode(t, id, signBinding(t, e.person, binding))
	body, isError = e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "signature": code})
	require.False(t, isError, "%v", body)
	requireWidenedAnswer(t, body, "APPLIED")
	require.Equal(t, "2", fmt.Sprint(body["rows"]))
	require.NotEqual(t, "bot", leadStatus(t, e.d, 30), "bot's row was restored")
	require.NotEqual(t, "helper", leadStatus(t, e.d, 32), "helper's row, which the person added, was restored")
}

// A bad code for a widened revert is still refused, by Postgres now, with
// the same codes and reasons as before; nothing is applied, and no answer
// gives the agent a link to the person's scope.
func TestRequestRevertRefusesBadCodesForAWidenedRevert(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	ownBinding, binding := e.widen(t, id, agentSecret)
	refused := func(code, reason string) {
		t.Helper()
		body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "signature": code})
		requireNoLink(t, requireErrorSteps(t, body, isError, "REVERT_INVALID", reason))
		require.NotContains(t, str(t, body["personMessage"]), e.task.String(), "the person's scope is not named")
	}

	tampered := signBinding(t, e.person, binding)
	tampered.Signature = bytes.Clone(tampered.Signature)
	tampered.Signature[len(tampered.Signature)-1] ^= 1
	refused(revertCode(t, id, tampered), "BAD_SIGNATURE")

	// A signature over another text: the agent's own proposal, which it
	// could read before the widen.
	refused(revertCode(t, id, signBinding(t, e.person, ownBinding)), "BAD_SIGNATURE")

	stranger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	refused(revertCode(t, id, signBinding(t, stranger, binding)), "PASSKEY_REVOKED")

	other := uuid.Must(uuid.NewV7())
	refused(revertCode(t, other, signBinding(t, e.person, binding)), "BAD_SIGNATURE")

	require.Equal(t, "bot", leadStatus(t, e.d, 30), "nothing was reverted")
	require.Equal(t, "helper", leadStatus(t, e.d, 32), "nothing was reverted")
	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "waitForSignature": 0})
	require.False(t, isError, "%v", body)
	requireWidenedAnswer(t, body, "PENDING")
	require.NotContains(t, str(t, body["personMessage"]), e.task.String())

	// Expired: the message names no scope; asking again names bot's own
	// task, with no filters.
	e.d.Exec(t, `UPDATE basalt_meta.reverts SET expires_at = now() - interval '1 second' WHERE revert_id = $1`, id)
	body, isError = e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "waitForSignature": 0})
	require.False(t, isError, "%v", body)
	requireWidenedAnswer(t, body, "EXPIRED")
	require.NotContains(t, str(t, body["personMessage"]), e.task.String())
	steps := requireResultSteps(t, body, "EXPIRED")
	require.Equal(t, map[string]any{"taskId": e.task.String()}, steps[1]["arguments"])
}
