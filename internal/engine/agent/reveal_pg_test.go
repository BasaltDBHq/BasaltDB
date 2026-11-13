package agent_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// The agent cannot reveal hidden rows (CONTRACT.md, Approvals, Rows hidden
// from the agent; plan task 7): holding the link secret, or its own role's
// credential, it gets no value without the person's passkey proof, and
// after the person revealed rows everything the agent reads stays as it
// was.

// revealSetup: bot may read and write leads only. Its first run deleted
// lead 5 with the person's approval (the cascade deleted notes 9 and 10
// and their tags, which bot cannot read) and it requested that run's
// revert; its second run holds a delete of lead 20 (notes 39 and 40).
type revealSetup struct {
	env      agentEnv
	pages    localPages
	doneRun  string
	heldRun  string
	approval string
	apSecret string
	revertID string
	rvSecret string
	// heldBody is the write's APPROVAL_REQUIRED body for lead 20.
	heldBody string
}

const dropLead = "DELETE FROM leads WHERE id = $1"

func newRevealSetup(t *testing.T) revealSetup {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	s := revealSetup{env: env, pages: newLocalPages(t, env)}

	// The first run: lead 5 deleted with the person's approval, then its
	// revert requested.
	s.doneRun = startRun(t, env.h, "Drop lead 5")
	args := map[string]any{"sql": dropLead, "params": []any{5}, "intent": "Lead 5 is a duplicate", "runId": s.doneRun}
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	id, secret := str(t, ap["approvalId"]), links.SecretOf(str(t, ap["approvalUrl"]))
	require.Equal(t, http.StatusOK, s.pages.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret,
		s.pages.signApproval(id, secret, env.person), nil))
	args["approvalId"] = id
	body, isError = env.h.call(t, "write", args)
	require.False(t, isError, "%v", body)

	rv := requestRevert(t, env.h, map[string]any{"runId": s.doneRun, "intent": "Undo the duplicate drop"})
	s.revertID, s.rvSecret = str(t, rv["revertId"]), links.SecretOf(str(t, rv["revertUrl"]))
	require.NotEmpty(t, s.rvSecret, "a short link to the revert")

	// The second run: a held delete of lead 20.
	s.heldRun = startRun(t, env.h, "Drop lead 20")
	body, isError = env.h.call(t, "write", map[string]any{"sql": dropLead, "params": []any{20}, "intent": "Lead 20 left", "runId": s.heldRun})
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap = approvalOf(t, body)
	s.approval, s.apSecret = str(t, ap["approvalId"]), links.SecretOf(str(t, ap["approvalUrl"]))
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	s.heldBody = string(raw)

	// The person's passkey is a synced one from here on: its counter stays
	// 0, so only the nonce stops a replay.
	d.Exec(t, `UPDATE basalt_meta.passkeys SET sign_count = 0`)
	return s
}

func startRun(t *testing.T, h harness, intent string) string {
	t.Helper()
	run, isError := h.call(t, "run_start", map[string]any{"intent": intent})
	require.False(t, isError, "%v", run)
	return str(t, run["runId"])
}

// zeroCounted makes an assertion a synced passkey's (counter 0).
func zeroCounted(a *passkey.Assertion) {
	const counterAt = 33
	binary.BigEndian.PutUint32(a.AuthenticatorData[counterAt:], 0)
}

// approvalRequest and revertRequest are what the page holds for a reveal:
// the request, with its reveal nonce, and the binding's rowsHash.
func (s revealSetup) approvalRequest(t *testing.T) (approval.Request, approval.Binding) {
	t.Helper()
	var req approval.Request
	require.Equal(t, http.StatusOK, s.pages.get("/api/v1/approvals/"+s.approval, s.apSecret, &req))
	b, err := req.Check()
	require.NoError(t, err)
	return req, b
}

func (s revealSetup) revertRequest(t *testing.T) (revert.Request, revert.Binding) {
	t.Helper()
	var req revert.Request
	require.Equal(t, http.StatusOK, s.pages.get("/api/v1/reverts/"+s.revertID, s.rvSecret, &req))
	b, err := req.Check()
	require.NoError(t, err)
	return req, b
}

// revealBody is a reveal body: sign signs the challenge (the person's
// passkey, or anything an agent can make), with a fresh reveal secret.
func revealBody(t *testing.T, sign func(challenge []byte) passkey.Assertion, kind string, id uuid.UUID, nonce []byte, rowsHash string) []byte {
	t.Helper()
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	key, err := approval.RevealKey(raw)
	require.NoError(t, err)
	ch, err := approval.RevealChallenge(kind, id, nonce, key, rowsHash)
	require.NoError(t, err)
	as := sign(ch)
	body, err := json.Marshal(agent.RevealRequest{RevealSecret: base64.RawURLEncoding.EncodeToString(raw), Proof: agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
	require.NoError(t, err)
	return body
}

func (s revealSetup) personSigns(t *testing.T) func([]byte) passkey.Assertion {
	return func(ch []byte) passkey.Assertion {
		as, err := s.env.person.Sign(ch, passkeytest.FlagsUPUV, zeroCounted)
		require.NoError(t, err)
		return as
	}
}

// agentViews is everything the agent role reads about its work through
// the views, ROWS_REVEALED ledger rows aside (agent_ledger shows them as
// they are: hashes and counts only).
func agentViews(t *testing.T, c *pgx.Conn) string {
	t.Helper()
	var out string
	require.NoError(t, c.QueryRow(context.Background(), `SELECT concat_ws(E'\n---\n',
		(SELECT string_agg(l::text, E'\n' ORDER BY l.seq) FROM basalt_meta.agent_ledger l WHERE l.kind <> 'ROWS_REVEALED'),
		(SELECT string_agg(a::text, E'\n' ORDER BY a.approval_id) FROM basalt_meta.agent_approvals a),
		(SELECT string_agg(r::text, E'\n' ORDER BY r.revert_id) FROM basalt_meta.agent_reverts r),
		(SELECT string_agg(l::text, E'\n' ORDER BY l.revert_id, l.line_no) FROM basalt_meta.agent_revert_lines l))`).Scan(&out))
	return out
}

// toolViews is what the agent's tools answer about the same work.
func (s revealSetup) toolViews(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, call := range map[string]struct {
		tool string
		args map[string]any
	}{
		"query":          {"query", map[string]any{"sql": "SELECT * FROM lead_notes WHERE lead_id IN (5, 20)", "runId": s.heldRun}},
		"list_pending":   {"list_pending", map[string]any{}},
		"preview_revert": {"preview_revert", map[string]any{"runId": s.doneRun}},
		"request_revert": {"request_revert", map[string]any{"revertId": s.revertID, "waitForSignature": 0}},
		"revert_plan":    {"revert_plan", map[string]any{"revertId": s.revertID}},
	} {
		body, _ := s.env.h.call(t, call.tool, call.args)
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		out[name] = string(raw)
	}
	return out
}

// The person's reveal works once for each item; every other way the agent
// can post to …/reveal with the link secret is refused, returns nothing,
// and leaves the nonce as it was. Afterwards every view and tool answer the
// agent reads is byte for byte what it was.
func TestAgentCannotRevealHiddenRows(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	// The tools first: a refused query records a REFUSED row, which the
	// views snapshot then includes.
	tools := s.toolViews(t)
	views := agentViews(t, s.env.a.Conn)
	require.NotContains(t, views, "note 39", "the agent's views hold no hidden value")
	require.NotContains(t, views, "note 40")
	require.NotContains(t, s.heldBody, "note 39", "the write's APPROVAL_REQUIRED body holds no hidden value")
	require.Contains(t, s.heldBody, "2 cascaded rows", "it says how many")

	req, b := s.approvalRequest(t)
	id := uuid.MustParse(s.approval)
	path := "/api/v1/approvals/" + s.approval + "/reveal"
	agentMade := func(ch []byte) passkey.Assertion {
		return passkey.Assertion{CredentialID: []byte("x"), AuthenticatorData: make([]byte, 37), ClientDataJSON: ch, Signature: []byte{0x30, 0}}
	}
	approvalSig := func([]byte) passkey.Assertion {
		as, err := s.env.person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, zeroCounted)
		require.NoError(t, err)
		return as
	}
	widenKey, err := revert.RescopeKey(make([]byte, links.SecretBytes))
	require.NoError(t, err)
	widenProof := func([]byte) passkey.Assertion {
		as, err := s.env.person.Sign(revert.RescopeChallenge(id, req.RevealNonce, widenKey, `{}`), passkeytest.FlagsUPUV, zeroCounted)
		require.NoError(t, err)
		return as
	}
	valid := revealBody(t, s.personSigns(t), approval.KindApprove, id, req.RevealNonce, b.RowsHash)
	for name, c := range map[string]struct {
		origin string
		body   []byte
		status int
	}{
		"no proof":                {pageOrigin, []byte(`{"revealSecret":"AAECAwQFBgcICQoLDA0ODw"}`), http.StatusBadRequest},
		"a forged Origin":         {"http://localhost:9999", valid, http.StatusForbidden},
		"no Origin":               {"", valid, http.StatusForbidden},
		"a proof the agent made":  {pageOrigin, revealBody(t, agentMade, approval.KindApprove, id, req.RevealNonce, b.RowsHash), http.StatusConflict},
		"an approval assertion":   {pageOrigin, revealBody(t, approvalSig, approval.KindApprove, id, req.RevealNonce, b.RowsHash), http.StatusConflict},
		"a widen proof":           {pageOrigin, revealBody(t, widenProof, approval.KindApprove, id, req.RevealNonce, b.RowsHash), http.StatusConflict},
		"a proof of another kind": {pageOrigin, revealBody(t, s.personSigns(t), approval.KindRevert, id, req.RevealNonce, b.RowsHash), http.StatusConflict},
	} {
		var out map[string]any
		status := s.pages.post(path, c.origin, s.apSecret, c.body, &out)
		require.Equal(t, c.status, status, "%s: %v", name, out)
		require.NotContains(t, out, "rows", name)
		if c.status == http.StatusConflict {
			require.Equal(t, guard.RevealRefused, out["reason"], name)
		}
		again, _ := s.approvalRequest(t)
		require.Equal(t, req.RevealNonce, again.RevealNonce, "%s: the nonce is unchanged", name)
	}

	// The person's proof works once; replayed, it is refused.
	var answer approval.RevealAnswer
	require.Equal(t, http.StatusOK, s.pages.post(path, pageOrigin, s.apSecret, valid, &answer))
	require.Len(t, answer.Rows, 2)
	used, _ := s.approvalRequest(t)
	require.NotEqual(t, req.RevealNonce, used.RevealNonce, "a valid use replaces the nonce")
	var replay map[string]any
	require.Equal(t, http.StatusConflict, s.pages.post(path, pageOrigin, s.apSecret, valid, &replay))
	require.Equal(t, guard.RevealRefused, replay["reason"])
	after, _ := s.approvalRequest(t)
	require.Equal(t, used.RevealNonce, after.RevealNonce, "a replay changes nothing")

	// The revert: the agent's own proof is refused, the person's works.
	rreq, rb := s.revertRequest(t)
	rid := uuid.MustParse(s.revertID)
	rpath := "/api/v1/reverts/" + s.revertID + "/reveal"
	var refused map[string]any
	require.Equal(t, http.StatusConflict, s.pages.post(rpath, pageOrigin, s.rvSecret,
		revealBody(t, agentMade, approval.KindRevert, rid, rreq.RevealNonce, rb.RowsHash), &refused))
	require.Equal(t, guard.RevealRefused, refused["reason"])
	var ranswer approval.RevealAnswer
	require.Equal(t, http.StatusOK, s.pages.post(rpath, pageOrigin, s.rvSecret,
		revealBody(t, s.personSigns(t), approval.KindRevert, rid, rreq.RevealNonce, rb.RowsHash), &ranswer))
	require.Len(t, ranswer.Rows, 4)

	require.Equal(t, views, agentViews(t, s.env.a.Conn), "the agent's views read the same after the reveals")
	after2 := s.toolViews(t)
	for name, body := range tools {
		require.Equal(t, body, after2[name], "%s answers the same after the reveals", name)
		require.NotContains(t, body, "note 39", name)
		require.NotContains(t, body, "note 9\\\"", name)
	}
}

// As the agent role, straight to the guard: no row without the person's
// proof or a ticket a proven call minted.
func TestAgentRoleCannotRevealDirectly(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	ctx := context.Background()
	conn := s.env.a.Conn
	key, err := approval.RevealKey(make([]byte, links.SecretBytes))
	require.NoError(t, err)
	made := passkey.Assertion{CredentialID: []byte("x"), AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte("{}"), Signature: []byte{0x30, 0}}

	_, err = guard.RevealRevertRows(ctx, conn, uuid.MustParse(s.revertID), made, key)
	requireRevealRefused(t, err, guard.CodeRevertInvalid)
	_, err = guard.OpenReveal(ctx, conn, uuid.MustParse(s.approval), made, key)
	requireRevealRefused(t, err, guard.CodeApprovalInvalid)

	// A preview of the held write with a ticket the agent guessed.
	pool, err := agentdb.NewPool(ctx, s.env.a.URL, 1)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	store := agentdb.NewStore(pool, sqlguard.DefaultLimits(), time.Now)
	in := guard.Intent{RunID: uuid.MustParse(s.heldRun), Text: "Lead 20 left"}
	_, err = store.RevealPreview(ctx, in, sqlguard.OpDelete, dropLead, []any{json.Number("20")}, uuid.MustParse(s.approval), make([]byte, 16))
	requireRevealRefused(t, err, guard.CodeApprovalInvalid)
}

// An approval reveal answers ROWS_CHANGED when a hidden row changed since
// the hold; a re-run of other parameters or another statement, even with
// the person's ticket, is REVEAL_REFUSED.
func TestApprovalRevealRowsChangedAndMismatch(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	ctx := context.Background()
	req, b := s.approvalRequest(t)
	id := uuid.MustParse(s.approval)

	// The person's ticket, opened as the engine does.
	pool, err := agentdb.NewPool(ctx, s.env.a.URL, 1)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	store := agentdb.NewStore(pool, sqlguard.DefaultLimits(), time.Now)
	raw := make([]byte, links.SecretBytes)
	_, err = rand.Read(raw)
	require.NoError(t, err)
	key, err := approval.RevealKey(raw)
	require.NoError(t, err)
	ch, err := approval.RevealChallenge(approval.KindApprove, id, req.RevealNonce, key, b.RowsHash)
	require.NoError(t, err)
	ticket, err := store.OpenReveal(ctx, id, s.personSigns(t)(ch), key)
	require.NoError(t, err)
	in := guard.Intent{RunID: uuid.MustParse(s.heldRun), Text: "Lead 20 left"}
	_, err = store.RevealPreview(ctx, in, sqlguard.OpDelete, dropLead, []any{json.Number("21")}, id, ticket)
	requireRevealRefused(t, err, guard.CodeApprovalInvalid)
	_, err = store.RevealPreview(ctx, in, sqlguard.OpDelete, dropLead+" AND status IS NOT NULL", []any{json.Number("20")}, id, ticket)
	requireRevealRefused(t, err, guard.CodeApprovalInvalid)
	rows, err := store.RevealPreview(ctx, in, sqlguard.OpDelete, dropLead, []any{json.Number("20")}, id, ticket)
	require.NoError(t, err, "the held statement with its parameters")
	require.Len(t, rows, 2)

	// A person edits a hidden note: the page's reveal answers ROWS_CHANGED.
	s.env.d.Exec(t, `UPDATE public.lead_notes SET note = 'edited by a person' WHERE id = 39`)
	fresh, fb := s.approvalRequest(t)
	var out map[string]any
	status := s.pages.post("/api/v1/approvals/"+s.approval+"/reveal", pageOrigin, s.apSecret,
		revealBody(t, s.personSigns(t), approval.KindApprove, id, fresh.RevealNonce, fb.RowsHash), &out)
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "APPROVAL_INVALID", out["code"])
	require.Equal(t, "ROWS_CHANGED", out["reason"])
	require.NotContains(t, out, "rows")
}

// requireRevealRefused checks err is code with detail REVEAL_REFUSED.
func requireRevealRefused(t *testing.T, err error, code guard.Code) {
	t.Helper()
	got, ok := guard.CodeOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, code, got)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, guard.RevealRefused, pe.Detail)
}
