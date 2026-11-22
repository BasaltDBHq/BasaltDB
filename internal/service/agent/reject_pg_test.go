package agent_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

func rejectPath(id uuid.UUID) string { return "/api/v1/reverts/" + id.String() + "/reject" }

func requireGuardCode(t *testing.T, err error, want guardmodel.Code) {
	t.Helper()
	code, ok := guard.CodeOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, want, code)
}

func rejectBody(t *testing.T, note *string) []byte {
	t.Helper()
	b, err := json.Marshal(agent.RejectRequest{Note: note})
	require.NoError(t, err)
	return b
}

// rejectVia is the via of every REVERT_REJECTED row, read as the admin.
func (e *rescopeEnv) rejectVia(t *testing.T) []string {
	t.Helper()
	rows, err := e.d.Admin.Query(context.Background(), `SELECT detail ->> 'via' FROM basalt_meta.ledger WHERE kind = 'REVERT_REJECTED' ORDER BY seq`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}

// requireRejectedWait is the agent's wait form on a rejected revert: at
// once, REJECTED with when and the note, and a STOP.
func (e *rescopeEnv) requireRejectedWait(t *testing.T, id uuid.UUID, out agent.RejectResponse, note string) {
	t.Helper()
	body := requestRevert(t, e.h, map[string]any{"revertId": id.String(), "waitForSignature": 0})
	require.Equal(t, "REJECTED", body["status"])
	require.Equal(t, out.RejectedAt, body["rejectedAt"])
	if note == "" {
		require.NotContains(t, body, "note")
	}
	if note != "" {
		require.Equal(t, note, body["note"])
	}
	require.Contains(t, str(t, body["personMessage"]), "rejected on the signing page. Nothing was reverted.")
	require.Contains(t, str(t, body["personMessage"]), note)
	steps, ok := body["nextSteps"].([]any)
	require.True(t, ok)
	require.Len(t, steps, 1)
	step, ok := steps[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, string(mcp.ActionStop), step["action"])
}

// Before a widen the page rejects under the agent's link (LINK_OR_AGENT):
// the revert is REJECTED, the link is revoked, the agent's wait returns
// REJECTED with the note, and the person's signature made before the
// reject no longer applies.
func TestRejectRouteBeforeAWiden(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), secret, &read))
	signed := signBinding(t, e.person, read.Binding)
	applyBody := e.p.signRevertPage(id.String(), secret, e.person)

	var perr pageError
	tooLong := strings.Repeat("x", guardmodel.MaxRejectNote+1)
	empty := ""
	for name, body := range map[string][]byte{
		"a note over 500 characters": rejectBody(t, &tooLong),
		"an empty note":              rejectBody(t, &empty),
		"an unknown key":             []byte(`{"note":"x","store":"app"}`),
		"not an object":              []byte(`"stop"`),
	} {
		require.Equal(t, http.StatusBadRequest, e.p.post(rejectPath(id), pageOrigin, secret, body, &perr), name)
		require.Equal(t, "INVALID_ARGUMENT", perr.Code, name)
	}
	require.Equal(t, http.StatusForbidden, e.p.post(rejectPath(id), "http://evil.example", secret, rejectBody(t, nil), nil))
	require.Empty(t, e.rejectVia(t), "nothing was rejected")

	note := "Not this one: I fixed the leads by hand."
	var out agent.RejectResponse
	require.Equal(t, http.StatusOK, e.p.post(rejectPath(id), pageOrigin, secret, rejectBody(t, &note), &out))
	require.Equal(t, agent.RejectResponse{RevertID: id.String(), Status: "REJECTED", RejectedAt: out.RejectedAt}, out)
	at, err := time.Parse(time.RFC3339, out.RejectedAt)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), at, time.Minute)
	require.Equal(t, []string{guardmodel.RejectViaLinkOrAgent}, e.rejectVia(t))

	// The link is revoked: read, apply and reject read as an unknown id.
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), secret, &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, http.StatusNotFound, e.p.post(revertPath(id)+"/apply", pageOrigin, secret, applyBody, &perr))
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(id), pageOrigin, secret, rejectBody(t, nil), &perr))

	e.requireRejectedWait(t, id, out, note)

	// The signature the person made before the reject applies nothing.
	_, err = guard.ApplyRevert(context.Background(), e.bot.Conn, id, signed)
	requireGuardCode(t, err, guardmodel.CodeRevertInvalid)
	var status string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT status FROM public.leads WHERE id = 30`).Scan(&status))
	require.Equal(t, "bot", status, "nothing was reverted")
}

// After a widen only the person's rotated link rejects: the agent's old
// link is refused, the agent role calling reject_revert itself without the
// token is refused, and after an engine restart (the token is gone) the
// page's reject is refused until the person widens again. The reject that
// goes through records SCOPE_TOKEN.
func TestRejectRouteAfterAWiden(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	ctx := context.Background()
	id, agentSecret := e.request(t)
	newSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret,
		e.widenBody(t, e.person, id, e.nonce(t, id, agentSecret), e.every(), newSecret), nil))

	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(id), pageOrigin, agentSecret, rejectBody(t, nil), &perr),
		"the agent's old link cannot reject")
	_, err := guard.RejectRevert(ctx, e.bot.Conn, id, "", nil)
	requireGuardCode(t, err, guardmodel.CodeRevertInvalid)
	require.ErrorContains(t, err, "REVERT_INVALID")

	// The engine restarts: the person's link still opens, but the token is
	// gone, so the reject is refused and nothing changes.
	e.start(t, nil)
	require.Equal(t, http.StatusConflict, e.p.post(rejectPath(id), pageOrigin, newSecret, rejectBody(t, nil), &perr))
	require.Equal(t, "REVERT_INVALID", perr.Code)
	require.NotEmpty(t, perr.PersonMessage)
	require.Empty(t, e.rejectVia(t))
	require.Equal(t, "PENDING", revertStatus(t, e.h, id.String()))

	// The person widens again (the page reads the nonce from the 409) and
	// rejects under the new link.
	again := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, newSecret,
		e.widenBody(t, e.person, id, e.nonce(t, id, newSecret), e.every(), again), nil))
	var out agent.RejectResponse
	require.Equal(t, http.StatusOK, e.p.post(rejectPath(id), pageOrigin, again, rejectBody(t, nil), &out))
	require.Equal(t, "REJECTED", out.Status)
	require.Equal(t, []string{guardmodel.RejectViaScopeToken}, e.rejectVia(t))
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), again, &perr), "the rejected revert's link is revoked")
	e.requireRejectedWait(t, id, out, "")
}

// Another agent's revert and an unknown id answer the reject route alike,
// and the other agent's revert stays pending.
func TestRejectRouteOthersRevertsReadAsUnknown(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	ctx := context.Background()
	_, secret := e.request(t)
	theirs, err := guard.PrepareRevert(ctx, e.helper.Conn, guardmodel.RevertScope{Kind: revert.ScopeTask, ID: e.task}, "x")
	require.NoError(t, err)
	unknown := uuid.Must(uuid.NewV7())

	var theirsBody, unknownBody json.RawMessage
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(theirs.RevertID), pageOrigin, secret, rejectBody(t, nil), &theirsBody))
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(unknown), pageOrigin, secret, rejectBody(t, nil), &unknownBody))
	require.JSONEq(t, string(unknownBody), string(theirsBody))
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(theirs.RevertID), pageOrigin, "", rejectBody(t, nil), &theirsBody))
	require.JSONEq(t, string(unknownBody), string(theirsBody))
	var rejected bool
	require.NoError(t, e.d.Admin.QueryRow(ctx, `SELECT rejected_at IS NOT NULL FROM basalt_meta.reverts WHERE revert_id = $1`, theirs.RevertID).Scan(&rejected))
	require.False(t, rejected)
}

// When Postgres refuses the scope token the engine holds for the person's
// link (the person's scope is gone: here the stored token no longer
// matches), the engine drops what it held and answers LINK_RESET, as it does
// when it sees the reset first; the link is revoked as by a reset, and
// nothing is rejected.
func TestRejectRouteAnswersLinkResetWhenTheHeldTokenIsRefused(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	newSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret,
		e.widenBody(t, e.person, id, e.nonce(t, id, agentSecret), e.every(), newSecret), nil))
	e.d.Exec(t, `UPDATE basalt_meta.reverts SET scope_token_hash = sha256('another token'::bytea) WHERE revert_id = $1`, id)

	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.post(rejectPath(id), pageOrigin, newSecret, rejectBody(t, nil), &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, "LINK_RESET", perr.Reason)
	require.NotEmpty(t, perr.PersonMessage)
	require.Empty(t, e.rejectVia(t), "nothing was rejected")
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), newSecret, &perr))
	require.Equal(t, "LINK_RESET", perr.Reason, "the page keeps saying the link was reset")
	require.Equal(t, "PENDING", revertStatus(t, e.h, id.String()))
}
