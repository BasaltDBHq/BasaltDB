package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// syncBuffer is a log sink the tests read back.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// revealEnv: bot may read and write leads only; it holds a delete of lead
// 20, which cascades to notes 39 and 40 that it cannot read,
// and has prepared the revert of an earlier run that deleted lead 5 with
// the person's approval (notes 9 and 10 and their tags, hidden). The
// service logs at debug level into logs.
type revealEnv struct {
	d       *guardtest.DB
	person  *passkeytest.Authenticator
	svc     *agent.Service
	secrets *links.Secrets
	logs    *syncBuffer
	held    uuid.UUID
	lines   []string
	revert  guard.PreparedRevert
}

func newRevealEnv(t *testing.T) *revealEnv {
	t.Helper()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	leads := []string{"public.leads"}
	bot := d.NewAgent(t, "bot", leads, leads)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))

	pg := newPGAgent(t, bot.URL, 2)
	store := pg.store
	e := &revealEnv{d: d, person: person, secrets: links.NewSecrets(time.Now, rand.Reader), logs: &syncBuffer{}}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The revert: lead 5 deleted under the person's approval, then prepared.
	done := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Drop lead 5"}
	require.NoError(t, guard.StartRun(ctx, bot.Conn, done))
	e.hold(t, store, done, 5, func(id uuid.UUID, binding string) {
		as, err := person.Sign(approval.Challenge(binding), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = store.SubmitApproval(ctx, id, as)
		require.NoError(t, err)
		_, err = store.WriteApproved(ctx, done, id, sqlguard.OpDelete, `DELETE FROM public.leads WHERE id = $1`, []any{json.Number("5")})
		require.NoError(t, err)
	})
	e.revert, err = store.PrepareRevert(ctx, guard.RevertScope{Kind: revert.ScopeRun, ID: done.RunID}, "Undo it", agent.RescopeTimeout)
	require.NoError(t, err)

	// The held write the page reveals.
	held := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Drop lead 20"}
	require.NoError(t, guard.StartRun(ctx, bot.Conn, held))
	e.hold(t, store, held, 20, func(id uuid.UUID, _ string) { e.held = id })
	// The person's passkey is a synced one: its counter stays 0.
	d.Exec(t, `UPDATE basalt_meta.passkeys SET sign_count = 0`)

	e.svc = pg.service(func(d *agent.Deps) {
		d.Log, d.PagesBase, d.Links, d.Relay = log, links.Portal, e.secrets, &lateRelay{}
	})
	return e
}

// hold previews and holds a delete of lead id as the engine does, then
// hands the approval to then.
func (e *revealEnv) hold(t *testing.T, store *agentdb.Store, in guard.Intent, id int, then func(uuid.UUID, string)) {
	t.Helper()
	ctx := context.Background()
	stmt, params := `DELETE FROM public.leads WHERE id = $1`, []any{json.Number(strconv.Itoa(id))}
	lines, err := store.Preview(ctx, in, stmt, params, []string{})
	require.NoError(t, err)
	held, err := store.Hold(ctx, in, guard.HoldRequest{Statement: stmt, Params: params, Assigned: []string{}, Lines: lines})
	require.NoError(t, err)
	if id == 20 {
		e.lines = lines
	}
	then(held.ApprovalID, held.BindingText)
}

// body is the page's reveal body for kind and id: the person's proof over
// the reveal challenge with the nonce and rowsHash the page holds.
func (e *revealEnv) body(t *testing.T, kind string, id uuid.UUID, nonce []byte, rowsHash string) (string, string) {
	t.Helper()
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	key, err := approval.RevealKey(raw)
	require.NoError(t, err)
	ch, err := approval.RevealChallenge(kind, id, nonce, key, rowsHash)
	require.NoError(t, err)
	as, err := e.person.Sign(ch, passkeytest.FlagsUPUV, zeroCounter)
	require.NoError(t, err)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	b, err := json.Marshal(agent.RevealRequest{RevealSecret: secret, Proof: agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
	require.NoError(t, err)
	return string(b), secret
}

// zeroCounter makes an assertion a synced passkey's.
func zeroCounter(a *passkey.Assertion) {
	copy(a.AuthenticatorData[33:37], []byte{0, 0, 0, 0})
}

func rowHashOf(row string) string {
	sum := sha256.Sum256([]byte(row))
	return hex.EncodeToString(sum[:])
}

// On loopback and in a Vault session the person's proof reveals the hidden
// rows, which hash to the lines the page holds; a wrong link secret is 404
// and a refused proof 409 REVEAL_REFUSED. No value, ticket or secret
// reaches the engine's log.
func TestRevealRoutes(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	ctx := context.Background()
	loopback := pages.New(links.Portal, slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	loopback.Add(e.svc)
	viaLoopback := func(method, path, secret, body string) (int, string) {
		t.Helper()
		headers := pagetest.Headers(secret)
		if method == http.MethodPost {
			headers = pagetest.PostHeaders(secret)
		}
		req := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		loopback.Handler().ServeHTTP(rec, req)
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		return rec.Code, rec.Body.String()
	}

	// The approval page on loopback.
	approvalSecret, err := e.secrets.Issue(e.held, time.Now().Add(time.Hour))
	require.NoError(t, err)
	readPath := "/api/v1/approvals/" + e.held.String()
	status, out := viaLoopback(http.MethodGet, readPath, approvalSecret, "")
	require.Equal(t, http.StatusOK, status, out)
	var req approval.Request
	require.NoError(t, json.Unmarshal([]byte(out), &req))
	require.Len(t, req.RevealNonce, 16, "the engine serves the reveal nonce")
	b, err := req.Check()
	require.NoError(t, err)

	body, revealSecret := e.body(t, approval.KindApprove, e.held, req.RevealNonce, b.RowsHash)
	status, _ = viaLoopback(http.MethodPost, readPath+"/reveal", "wrong", body)
	require.Equal(t, http.StatusNotFound, status, "a wrong link secret reads as an unknown id")
	status, out = viaLoopback(http.MethodPost, readPath+"/reveal", approvalSecret, body)
	require.Equal(t, http.StatusOK, status, out)
	var answer approval.RevealAnswer
	require.NoError(t, json.Unmarshal([]byte(out), &answer))
	checked, err := approval.CheckRevealAnswer(req.Lines, answer)
	require.NoError(t, err)
	require.Equal(t, []bool{true, true}, checked)
	require.Contains(t, out, "note 39")

	// The same proof again: the nonce is used, one fixed refusal.
	status, refused := viaLoopback(http.MethodPost, readPath+"/reveal", approvalSecret, body)
	require.Equal(t, http.StatusConflict, status, refused)
	require.Contains(t, refused, `"reason":"REVEAL_REFUSED"`)
	status, after := viaLoopback(http.MethodGet, readPath, approvalSecret, "")
	require.Equal(t, http.StatusOK, status)
	var reread approval.Request
	require.NoError(t, json.Unmarshal([]byte(after), &reread))
	require.Equal(t, req.Lines, reread.Lines, "the request still carries the redacted lines")
	require.NotEqual(t, req.RevealNonce, reread.RevealNonce, "a new nonce for the next reveal")

	// The revert page in a Vault session.
	s := serveOverVault(t, &wire{}, e.svc, e.secrets, e.revert.RevertID)
	p := s.open(t)
	wctx := waitCtx(t)
	do := func(method, path, secret, body string) pagetest.Reply {
		t.Helper()
		headers := pagetest.Headers(secret)
		if method == http.MethodPost {
			headers = pagetest.PostHeaders(secret)
		}
		r, err := p.Do(wctx, method, path, headers, body, 0)
		require.NoError(t, err)
		return r
	}
	revertPath := "/api/v1/reverts/" + e.revert.RevertID.String()
	r := do(http.MethodGet, revertPath, s.secret, "")
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var rreq revert.Request
	require.NoError(t, json.Unmarshal([]byte(r.Body), &rreq))
	require.Len(t, rreq.RevealNonce, 16)
	rb, err := rreq.Check()
	require.NoError(t, err)
	rbody, _ := e.body(t, approval.KindRevert, e.revert.RevertID, rreq.RevealNonce, rb.RowsHash)
	bad, _ := e.body(t, approval.KindApprove, e.revert.RevertID, rreq.RevealNonce, rb.RowsHash)
	r = do(http.MethodPost, revertPath+"/reveal", s.secret, bad)
	require.Equal(t, http.StatusConflict, r.Status, r.Body)
	require.Contains(t, r.Body, `"reason":"REVEAL_REFUSED"`)
	r = do(http.MethodPost, revertPath+"/reveal", s.secret, rbody)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var ranswer approval.RevealAnswer
	require.NoError(t, json.Unmarshal([]byte(r.Body), &ranswer))
	require.Len(t, ranswer.Rows, 4, "notes 9 and 10 and their tags")
	for _, row := range ranswer.Rows {
		var l struct {
			RowHash string `json:"rowHash"`
		}
		require.NoError(t, json.Unmarshal([]byte(rreq.Lines[row.Line]), &l))
		require.Equal(t, l.RowHash, rowHashOf(row.Row))
	}

	// The person signs the revert; a reveal after it gets the revert's
	// normal answer, since the signature took the row first.
	sig, err := e.person.Sign(revert.Challenge(rreq.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, _, err = e.svc.RelayRevert(ctx, revert.Response{
		RevertID: e.revert.RevertID, CredentialID: sig.CredentialID,
		AuthenticatorData: sig.AuthenticatorData, ClientDataJSON: sig.ClientDataJSON, Signature: sig.Signature,
	})
	require.NoError(t, err)
	late, _ := e.body(t, approval.KindRevert, e.revert.RevertID, rreq.RevealNonce, rb.RowsHash)
	status, out = viaLoopback(http.MethodPost, revertPath+"/reveal", s.secret, late)
	require.Equal(t, http.StatusConflict, status, out)
	require.Contains(t, out, `"code":"REVERT_INVALID"`)

	logs := e.logs.String()
	for _, secretText := range []string{"note 39", "note 40", "note 9", "tag 10", revealSecret} {
		require.NotContains(t, logs, secretText, "the log carries no revealed value or secret")
	}
}
