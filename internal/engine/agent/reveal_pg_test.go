package agent_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// The agent cannot reveal hidden rows (CONTRACT.md, Approvals, Rows hidden
// from the agent): holding the link secret, or its own role's
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
// revert_plan is checked on a large plan in TestRevertPlanStaysRedacted:
// for this one-call revert it has no plan to show.
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
	} {
		body, _ := s.env.h.call(t, call.tool, call.args)
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		out[name] = string(raw)
	}
	return out
}

// item is one of the setup's two items as its page sees it: the reveal
// route, the link secret, and what the reveal proof signs.
type item struct {
	kind   string
	id     uuid.UUID
	path   string
	secret string
	// state reads the request: its reveal nonce and the binding's rowsHash.
	state func(t *testing.T) ([]byte, string)
	// other signs the binding of the item (an approval or revert
	// signature, not a reveal proof).
	binding string
}

func (s revealSetup) items(t *testing.T) []item {
	t.Helper()
	ap, _ := s.approvalRequest(t)
	rv, _ := s.revertRequest(t)
	return []item{
		{
			kind: approval.KindApprove, id: uuid.MustParse(s.approval), path: "/api/v1/approvals/" + s.approval + "/reveal", secret: s.apSecret,
			binding: ap.Binding, state: func(t *testing.T) ([]byte, string) {
				req, b := s.approvalRequest(t)
				return req.RevealNonce, b.RowsHash
			},
		},
		{
			kind: approval.KindRevert, id: uuid.MustParse(s.revertID), path: "/api/v1/reverts/" + s.revertID + "/reveal", secret: s.rvSecret,
			binding: rv.Binding, state: func(t *testing.T) ([]byte, string) {
				req, b := s.revertRequest(t)
				return req.RevealNonce, b.RowsHash
			},
		},
	}
}

// hiddenValues are the values of the rows bot cannot read: what the
// person's reveals must return and nothing the agent reads may hold.
var hiddenValues = []string{"note 9", "note 10", "tag 9", "tag 10", "note 39", "note 40"}

// rowsRevealedDetails are the ROWS_REVEALED rows the agent reads in
// agent_ledger, each detail as text.
func rowsRevealedDetails(t *testing.T, c *pgx.Conn) []string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT detail::text FROM basalt_meta.agent_ledger WHERE kind = 'ROWS_REVEALED' ORDER BY seq`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// The person's reveal works once for each item; every other way the agent
// can post to …/reveal with the link secret is refused, returns nothing,
// and leaves the nonce as it was. Afterwards every view and tool answer the
// agent reads is byte for byte what it was, and none holds a revealed value.
func TestAgentCannotRevealHiddenRows(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	// The tools first: a refused query records a REFUSED row, which the
	// views snapshot then includes.
	tools := s.toolViews(t)
	views := agentViews(t, s.env.a.Conn)

	agentMade := func(ch []byte) passkey.Assertion {
		return passkey.Assertion{CredentialID: []byte("x"), AuthenticatorData: make([]byte, 37), ClientDataJSON: ch, Signature: []byte{0x30, 0}}
	}
	widenKey, err := revert.RescopeKey(make([]byte, links.SecretBytes))
	require.NoError(t, err)
	revealed := map[string]string{}
	for _, it := range s.items(t) {
		nonce, hash := it.state(t)
		signed := func(ch []byte) func([]byte) passkey.Assertion {
			return func([]byte) passkey.Assertion {
				as, err := s.env.person.Sign(ch, passkeytest.FlagsUPUV, zeroCounted)
				require.NoError(t, err)
				return as
			}
		}
		otherKind := approval.KindRevert
		if it.kind == approval.KindRevert {
			otherKind = approval.KindApprove
		}
		valid := revealBody(t, s.personSigns(t), it.kind, it.id, nonce, hash)
		for name, c := range map[string]struct {
			origin string
			body   []byte
			status int
		}{
			"no proof":                {pageOrigin, []byte(`{"revealSecret":"AAECAwQFBgcICQoLDA0ODw"}`), http.StatusBadRequest},
			"a forged Origin":         {"http://localhost:9999", valid, http.StatusForbidden},
			"no Origin":               {"", valid, http.StatusForbidden},
			"a proof the agent made":  {pageOrigin, revealBody(t, agentMade, it.kind, it.id, nonce, hash), http.StatusConflict},
			"the item's signature":    {pageOrigin, revealBody(t, signed(approval.Challenge(it.binding)), it.kind, it.id, nonce, hash), http.StatusConflict},
			"a widen proof":           {pageOrigin, revealBody(t, signed(revert.RescopeChallenge(it.id, nonce, widenKey, `{}`)), it.kind, it.id, nonce, hash), http.StatusConflict},
			"a proof of another kind": {pageOrigin, revealBody(t, s.personSigns(t), otherKind, it.id, nonce, hash), http.StatusConflict},
		} {
			var out map[string]any
			status := s.pages.post(it.path, c.origin, it.secret, c.body, &out)
			require.Equal(t, c.status, status, "%s %s: %v", it.kind, name, out)
			require.NotContains(t, out, "rows", name)
			if c.status == http.StatusConflict {
				require.Equal(t, guard.RevealRefused, out["reason"], "%s %s", it.kind, name)
			}
			again, _ := it.state(t)
			require.Equal(t, nonce, again, "%s %s: the nonce is unchanged", it.kind, name)
		}

		// The person's proof works once; replayed, it is refused.
		var answer approval.RevealAnswer
		require.Equal(t, http.StatusOK, s.pages.post(it.path, pageOrigin, it.secret, valid, &answer), it.kind)
		used, _ := it.state(t)
		require.NotEqual(t, nonce, used, "%s: a valid use replaces the nonce", it.kind)
		var replay map[string]any
		require.Equal(t, http.StatusConflict, s.pages.post(it.path, pageOrigin, it.secret, valid, &replay))
		require.Equal(t, guard.RevealRefused, replay["reason"])
		after, _ := it.state(t)
		require.Equal(t, used, after, "%s: a replay changes nothing", it.kind)
		for _, r := range answer.Rows {
			revealed[it.kind] += r.Row + "\n"
		}
	}
	all := revealed[approval.KindApprove] + revealed[approval.KindRevert]
	for _, v := range hiddenValues {
		require.Contains(t, all, `"`+v+`"`, "the person's reveals return %q", v)
	}

	// What the agent reads: the same as before, and no revealed value.
	require.Equal(t, views, agentViews(t, s.env.a.Conn), "the agent's views read the same after the reveals")
	after := s.toolViews(t)
	details := rowsRevealedDetails(t, s.env.a.Conn)
	require.Len(t, details, 2, "one ROWS_REVEALED per item")
	readable := make([]string, 0, 2+len(tools)+len(details))
	readable = append(readable, views, s.heldBody)
	for name, body := range tools {
		require.Equal(t, body, after[name], "%s answers the same after the reveals", name)
		readable = append(readable, body)
	}
	for _, d := range details {
		var detail map[string]any
		require.NoError(t, json.Unmarshal([]byte(d), &detail))
		keys := make([]string, 0, len(detail))
		for k := range detail {
			keys = append(keys, k)
		}
		require.Subset(t, []string{"kind", "id", "credentialId", "rows", "rowsChanged"}, keys, d)
		require.Subset(t, keys, []string{"kind", "id", "credentialId", "rows"}, d)
		readable = append(readable, d)
	}
	for _, text := range readable {
		for _, v := range hiddenValues {
			require.NotContains(t, text, v, "the agent reads no revealed value")
		}
	}
	require.Contains(t, s.heldBody, "2 cascaded rows", "the held write's body says how many it hides")
}

// A large plan whose lines bot can no longer read: revert_plan shows them
// redacted before and after the person reveals them, byte for byte.
func TestRevertPlanStaysRedactedAfterAReveal(t *testing.T) {
	t.Parallel()
	const rows = revert.MaxLines + 10
	d := guardtest.New(t)
	ctx := context.Background()
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, 'orig value ' || g FROM generate_series(1, %d) g`, rows))
	items := []string{"public.items"}
	bot := d.NewAgent(t, "bot", items, items)
	env := agentHarnessFor(t, d, bot, pageOrigin)
	p := newLocalPages(t, env)
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Bulk update items"}
	require.NoError(t, guard.StartRun(ctx, bot.Conn, in))
	stmts := make([]string, 0, rows/10)
	for i := 0; i < rows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'agent' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, bot.Conn, in, stmts...))
	d.Exec(t, `REVOKE SELECT ON public.items FROM `+bot.Role+`, `+d.Names.Agents())
	rv := requestRevert(t, env.h, map[string]any{"runId": in.RunID.String(), "intent": "Undo the bulk update"})
	id := str(t, rv["revertId"])

	// revert_plan issues the plan's link again each time (CONTRACT.md, Link
	// secrets): its lines are compared, and the page uses the newest link.
	plan := func() (string, string) {
		body, isError := env.h.call(t, "revert_plan", map[string]any{"revertId": id, "limit": 20})
		require.False(t, isError, "%v", body)
		raw, err := json.Marshal(body["items"])
		require.NoError(t, err)
		given, ok := body["links"].([]any)
		require.True(t, ok, "%v", body)
		link, ok := given[0].(map[string]any)
		require.True(t, ok)
		return string(raw), links.SecretOf(str(t, link["url"]))
	}
	before, secret := plan()
	require.Contains(t, before, `"redacted":true`, "the plan's lines are redacted for bot")
	d.Exec(t, `UPDATE basalt_meta.passkeys SET sign_count = 0`)

	var req revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &req))
	b, err := req.Check()
	require.NoError(t, err)
	s := revealSetup{env: env}
	var answer approval.RevealAnswer
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/reveal", pageOrigin, secret,
		revealBody(t, s.personSigns(t), approval.KindRevert, uuid.MustParse(id), req.RevealNonce, b.RowsHash), &answer))
	require.Len(t, answer.Rows, revert.MaxLines)
	require.Contains(t, answer.Rows[0].Row, "orig value ", "the person sees the values")

	after, _ := plan()
	require.Equal(t, before, after, "revert_plan lists the same lines after the reveal")
	require.NotContains(t, after, "orig value ")
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
	store := pgService(t, s.env.a.URL, withConns(1)).Store
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
	store := pgService(t, s.env.a.URL, withConns(1)).Store
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
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
