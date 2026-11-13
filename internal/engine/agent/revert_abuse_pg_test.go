package agent_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// Abuse tests of the revert scope routes (revert scope plan, Tests,
// "Abuse"): the agent that requested a revert holds its link secret and
// can send any Origin from loopback, so neither is an authority to widen.

// counterAt is where the signature counter sits in authenticator data
// (32-byte rpIdHash, then the flags byte).
const counterAt = 33

// syncedPasskey makes an assertion look like a synced passkey's, whose
// counter stays 0: only the nonce can stop a replay.
func syncedPasskey(a *passkey.Assertion) {
	binary.BigEndian.PutUint32(a.AuthenticatorData[counterAt:], 0)
}

// syncedWidenBody is widenBody signed by a passkey whose counter stays 0.
func (e *rescopeEnv) syncedWidenBody(t *testing.T, id uuid.UUID, nonce []byte, sel revert.Select, newSecret string) []byte {
	t.Helper()
	raw, err := links.DecodeSecret(newSecret)
	require.NoError(t, err)
	key, err := revert.RescopeKey(raw)
	require.NoError(t, err)
	selJSON, err := json.Marshal(sel)
	require.NoError(t, err)
	var norm string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	as, err := e.person.Sign(revert.RescopeChallenge(id, nonce, key, norm), passkeytest.FlagsUPUV, syncedPasskey)
	require.NoError(t, err)
	return scopeBody(t, agent.ScopeRequest{Select: sel, NewSecret: newSecret, Proof: &agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
}

// storedScope is what Postgres holds for the revert's scope, read as the
// admin: the binding, the nonce and how often it was rescoped.
type storedScope struct {
	Binding  string
	Nonce    []byte
	Rescoped int
}

func (e *rescopeEnv) storedScope(t *testing.T, id uuid.UUID) storedScope {
	t.Helper()
	var s storedScope
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT binding_text, rescope_nonce, rescoped
		FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&s.Binding, &s.Nonce, &s.Rescoped))
	return s
}

// requireNothingReturned checks a refused scope call's body: an error, and
// none of what a proven call returns (lines, catalog, binding, token).
func requireNothingReturned(t *testing.T, body map[string]any, name string) {
	t.Helper()
	require.Contains(t, body, "code", name)
	for _, key := range []string{"request", "lines", "catalog", "binding", "scopeToken", "agentRows"} {
		require.NotContains(t, body, key, name)
	}
}

// The agent holds only its link's secret and forges the page's Origin from
// loopback. Every widen it can build is refused with nothing returned:
// no proof, the person's proof pasted into the chat without the new
// secret it names, the proof with a secret of the agent's own, an
// approval-style assertion, and a proof made for another revert. Nothing
// changes in Postgres and the link keeps the agent's proposal.
func TestAnAgentHoldingTheLinkCannotWiden(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	other, _ := e.request(t)
	before := e.storedScope(t, id)
	nonce := e.nonce(t, id, agentSecret)

	// The person's real proof, as they might paste it into the chat: the
	// page's new secret it names never left the page.
	personSecret := newLinkSecret(t)
	var pasted agent.ScopeRequest
	require.NoError(t, json.Unmarshal(e.widenBody(t, e.person, id, nonce, e.every(), personSecret), &pasted))
	ownSecret := pasted
	ownSecret.NewSecret = newLinkSecret(t)
	var foreign agent.ScopeRequest
	require.NoError(t, json.Unmarshal(e.widenBody(t, e.person, other, e.nonce(t, other, agentSecretOf(t, e, other)), e.every(), personSecret), &foreign))
	approvalLike, err := e.person.Sign(revert.Challenge("{}"), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)

	cases := map[string][]byte{
		"no proof": scopeBody(t, agent.ScopeRequest{Select: e.every()}),
		"the pasted proof, with a secret of the agent's own": scopeBody(t, ownSecret),
		"another revert's proof":                             scopeBody(t, foreign),
		"a signature over a binding as the proof": scopeBody(t, agent.ScopeRequest{Select: e.every(), NewSecret: newLinkSecret(t),
			Proof: &agent.ScopeProof{CredentialID: approvalLike.CredentialID, AuthenticatorData: approvalLike.AuthenticatorData,
				ClientDataJSON: approvalLike.ClientDataJSON, Signature: approvalLike.Signature}}),
	}
	for name, body := range cases {
		var out map[string]any
		require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, agentSecret, body, &out), name)
		requireNothingReturned(t, out, name)
	}
	// The pasted proof with no secret at all is refused on its shape.
	var out map[string]any
	pasted.NewSecret = ""
	require.Equal(t, http.StatusBadRequest, e.p.post(scopePath(id), pageOrigin, agentSecret, scopeBody(t, pasted), &out))
	requireNothingReturned(t, out, "a proof without a secret")

	require.Equal(t, before, e.storedScope(t, id), "nothing changed")
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), agentSecret, &read), "the agent's link still works")
	b, err := read.Check()
	require.NoError(t, err)
	require.False(t, b.Widened)
}

// agentSecretOf is the link secret of revert id, issued again for the
// agent (reissueLink), so the test can read that revert's nonce.
func agentSecretOf(t *testing.T, e *rescopeEnv, id uuid.UUID) string {
	t.Helper()
	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "reissueLink": true})
	require.False(t, isError, "%v", body)
	return links.SecretOf(str(t, body["revertUrl"]))
}

// A widen proof is good for one widen. With a synced passkey (counter 0),
// the proof replayed through the page after it was used, or after the
// agent reset the revert, is refused with nothing returned: the nonce
// changed.
func TestAWidenProofIsNotReplayable(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	personSecret := newLinkSecret(t)
	proof := e.syncedWidenBody(t, id, e.nonce(t, id, agentSecret), e.every(), personSecret)
	var wide scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret, proof, &wide))
	widened := e.storedScope(t, id)

	// Replayed under the rotated link, naming a fresh secret: refused.
	var replay agent.ScopeRequest
	require.NoError(t, json.Unmarshal(proof, &replay))
	replay.NewSecret = newLinkSecret(t)
	var out map[string]any
	require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, personSecret, scopeBody(t, replay), &out))
	requireNothingReturned(t, out, "replayed after use")
	require.Equal(t, widened, e.storedScope(t, id), "the replay changed nothing")

	// The agent resets the revert to its proposal and gets a new link; the
	// person's proof, replayed under it, is refused.
	resetSecret := agentSecretOf(t, e, id)
	reset := e.storedScope(t, id)
	require.NotEqual(t, widened.Nonce, reset.Nonce, "the reset set a new nonce")
	for name, body := range map[string][]byte{"the used proof": proof, "the used proof, a fresh secret": scopeBody(t, replay)} {
		require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, resetSecret, body, &out), name)
		requireNothingReturned(t, out, name)
	}
	require.Equal(t, reset, e.storedScope(t, id), "nothing changed after the reset")
}
