package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
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
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// lateRelay is the agent's link relay once the Vault client exists.
type lateRelay struct{ c atomic.Pointer[vault.Client] }

func (r *lateRelay) Connected() bool {
	c := r.c.Load()
	return c != nil && c.Connected()
}

func (r *lateRelay) Register(ctx context.Context, token channel.LinkToken, expires time.Time) error {
	c := r.c.Load()
	if c == nil {
		return vault.ErrNotConnected
	}
	return c.Register(ctx, token, expires)
}

// A widen inside a Vault session behaves as on loopback: a refused widen
// gets the same answer, a proven one rotates the revert's link to the
// page's new secret while the session stays open, the old secret is
// refused inside the session and opens no new one, other sessions of the
// old link end, and the new secret opens a new session.
func TestVaultSessionWidensARevert(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	all := []string{"public.leads", "public.lead_owner"}
	bot, helper := d.NewAgent(t, "bot", all, all), d.NewAgent(t, "helper", all, all)
	ctx := context.Background()
	task := uuid.Must(uuid.NewV7())
	for _, w := range []struct {
		a   *guardtest.Agent
		sql string
	}{{bot, `UPDATE public.leads SET status = 'bot' WHERE id = 30`}, {helper, `UPDATE public.leads SET status = 'helper' WHERE id = 32`}} {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "work in the task"}
		require.NoError(t, guard.StartRun(ctx, w.a.Conn, in))
		require.NoError(t, guardtest.Guarded(ctx, w.a.Conn, in, w.sql))
	}
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))

	pool, err := agentdb.NewPool(ctx, bot.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	dbStore := agentdb.NewStore(pool, limits, time.Now)
	prep, err := dbStore.PrepareRevert(ctx, guard.RevertScope{Kind: revert.ScopeTask, ID: task}, "Undo the task", agent.RescopeTimeout)
	require.NoError(t, err)
	id := prep.RevertID

	secrets := links.NewSecrets(time.Now, rand.Reader)
	relay := &lateRelay{}
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: agentdb.NewReader(pool, limits, time.Now), Store: dbStore, Reads: dbStore, Approvals: dbStore,
		Reverts: dbStore, Log: quietLog(), Now: time.Now, PagesBase: links.Portal, Links: secrets, Relay: relay,
	})
	s := serveOverVault(t, &wire{}, svc, secrets, id)
	relay.c.Store(s.client)

	loopback := pages.New(links.Portal, quietLog())
	loopback.Add(svc)
	viaLoopback := func(path string, headers map[string]string, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		loopback.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	p := s.open(t)
	bystander := s.open(t)
	wctx := waitCtx(t)
	scopePath := "/api/v1/reverts/" + id.String() + "/scope"
	readPath := "/api/v1/reverts/" + id.String()
	do := func(pg *pagetest.Page, method, path, secret, body string) pagetest.Reply {
		t.Helper()
		headers := pagetest.Headers(secret)
		if method == http.MethodPost {
			headers = pagetest.PostHeaders(secret)
		}
		r, err := pg.Do(wctx, method, path, headers, body, 0)
		require.NoError(t, err)
		return r
	}

	// A refused widen reads the same in the session as on loopback.
	wider, err := json.Marshal(agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: task}})
	require.NoError(t, err)
	refused := do(p, http.MethodPost, scopePath, s.secret, string(wider))
	status, body := viaLoopback(scopePath, pagetest.PostHeaders(s.secret), string(wider))
	require.Equal(t, http.StatusConflict, refused.Status, refused.Body)
	require.Equal(t, status, refused.Status)
	require.Equal(t, body, refused.Body, "the session answers as loopback")
	// Whoever opened the session holds only the link secret (the agent can):
	// the refusal returns none of what a proven widen does.
	var refusal map[string]any
	require.NoError(t, json.Unmarshal([]byte(refused.Body), &refusal))
	require.Contains(t, refusal, "code")
	for _, key := range []string{"request", "lines", "catalog", "binding", "scopeToken"} {
		require.NotContains(t, refusal, key)
	}

	// The person's proven widen, with the page's new secret.
	raw := make([]byte, links.SecretBytes)
	_, err = rand.Read(raw)
	require.NoError(t, err)
	newSecret := base64.RawURLEncoding.EncodeToString(raw)
	key, err := revert.RescopeKey(raw)
	require.NoError(t, err)
	every := revert.Select{Scope: revert.ScopeTask, ScopeID: task}
	selJSON, err := json.Marshal(every)
	require.NoError(t, err)
	var norm string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	// The page reads the nonce from the engine, in the session.
	r0 := do(p, http.MethodGet, readPath, s.secret, "")
	require.Equal(t, http.StatusOK, r0.Status, r0.Body)
	var proposal revert.Request
	require.NoError(t, json.Unmarshal([]byte(r0.Body), &proposal))
	require.Len(t, proposal.RescopeNonce, 16)
	as, err := person.Sign(revert.RescopeChallenge(id, proposal.RescopeNonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	widen, err := json.Marshal(agent.ScopeRequest{Select: every, NewSecret: newSecret, Proof: &agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
	require.NoError(t, err)
	r := do(p, http.MethodPost, scopePath, s.secret, string(widen))
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var out agent.ScopeResponse
	require.NoError(t, json.Unmarshal([]byte(r.Body), &out))
	b, err := out.Request.Check()
	require.NoError(t, err)
	require.True(t, b.Widened)
	require.NotNil(t, out.Catalog)

	// The session stays open under the new secret; the old one is refused.
	r = do(p, http.MethodGet, readPath, newSecret, "")
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	require.Equal(t, http.StatusNotFound, do(p, http.MethodGet, readPath, s.secret, "").Status)

	// The old link's other session ended, and the old secret opens none.
	require.Equal(t, websocket.StatusCode(channel.ErrLinkRefused), bystander.Closed(wctx))
	_, err = pagetest.Open(wctx, s.v.URL(), s.keys)
	require.Error(t, err, "the old link opens no session")

	// The new secret opens a new session: the engine registered its token.
	keys, err := channel.DeriveLink(newSecret)
	require.NoError(t, err)
	fresh, err := pagetest.Open(wctx, s.v.URL(), keys)
	require.NoError(t, err)
	t.Cleanup(fresh.Close)
	r = do(fresh, http.MethodGet, readPath, newSecret, "")
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var read revert.Request
	require.NoError(t, json.Unmarshal([]byte(r.Body), &read))
	require.Equal(t, out.Request.Binding, read.Binding)
}
