package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// A reject inside a Vault session behaves as on loopback: a bad body gets
// the same answer, the reject is answered 200 before the revoked link ends
// the session with LINK_REFUSED, and the old secret opens no new session.
// After a widen in the session, the rotated secret rejects with the scope
// token the engine holds (SCOPE_TOKEN).
func TestVaultSessionRejectsARevert(t *testing.T) {
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

	pg := newPGAgent(t, bot.URL, 2)
	dbStore := pg.store
	prepare := func() uuid.UUID {
		prep, err := dbStore.PrepareRevert(ctx, action.Scope{Kind: revert.ScopeTask, ID: task}, "Undo the task", guardmodel.MCPPrepareTimeout)
		require.NoError(t, err)
		return prep.RevertID
	}
	id, widened := prepare(), prepare()

	secrets := links.NewSecrets(time.Now, rand.Reader)
	relay := &lateRelay{}
	svc := pg.service(func(d *agent.Deps) {
		d.Core.PagesBase, d.Delivery.Links, d.Delivery.Relay = links.Portal, secrets, relay
	})
	s := serveOverVault(t, &wire{}, svc, secrets, id)
	relay.c.Store(s.client)

	loopback := newPages(links.Portal, quietLog())
	loopback.Add(svc)
	viaLoopback := func(method, path string, headers map[string]string, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		loopback.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	wctx := waitCtx(t)
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
	via := func() []string {
		t.Helper()
		rows, err := d.Admin.Query(ctx, `SELECT detail ->> 'via' FROM basalt_meta.ledger WHERE kind = 'REVERT_REJECTED' ORDER BY seq`)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			require.NoError(t, rows.Scan(&v))
			out = append(out, v)
		}
		return out
	}

	// A bad body reads the same in the session as on loopback.
	p := s.open(t)
	rejectPath := "/api/v1/reverts/" + id.String() + "/reject"
	bad := `{"note":"","store":"x"}`
	refused := do(p, http.MethodPost, rejectPath, s.secret, bad)
	status, body := viaLoopback(http.MethodPost, rejectPath, pagetest.PostHeaders(s.secret), bad)
	require.Equal(t, http.StatusBadRequest, refused.Status, refused.Body)
	require.Equal(t, status, refused.Status)
	require.Equal(t, body, refused.Body, "the session answers as loopback")

	// The reject is answered, then the revoked link ends the session.
	r := do(p, http.MethodPost, rejectPath, s.secret, `{"note":"leave it"}`)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var out revertsvc.RejectResponse
	require.NoError(t, json.Unmarshal([]byte(r.Body), &out))
	require.Equal(t, id.String(), out.RevertID)
	require.Equal(t, "REJECTED", out.Status)
	require.Equal(t, websocket.StatusCode(channel.ErrLinkRefused), p.Closed(wctx))
	_, err = pagetest.Open(wctx, s.v.URL(), s.keys)
	require.Error(t, err, "the rejected revert's link opens no session")
	status, _ = viaLoopback(http.MethodGet, "/api/v1/reverts/"+id.String(), pagetest.Headers(s.secret), "")
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, []string{guardmodel.RejectViaLinkOrAgent}, via())

	// A second revert, widened in its session: the rotated secret rejects.
	secret2, token2, err := secrets.IssueRelay(widened, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, s.client.Register(ctx, token2, time.Now().Add(time.Hour)))
	keys2, err := channel.DeriveLink(secret2)
	require.NoError(t, err)
	p2, err := pagetest.Open(wctx, s.v.URL(), keys2)
	require.NoError(t, err)
	t.Cleanup(p2.Close)
	readPath := "/api/v1/reverts/" + widened.String()
	r0 := do(p2, http.MethodGet, readPath, secret2, "")
	require.Equal(t, http.StatusOK, r0.Status, r0.Body)
	var proposal revert.Request
	require.NoError(t, json.Unmarshal([]byte(r0.Body), &proposal))
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
	as, err := person.Sign(reverttest.RescopeChallenge(widened, proposal.RescopeNonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	widen, err := json.Marshal(revertsvc.ScopeRequest{Select: every, NewSecret: newSecret, Proof: &linksvc.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
	require.NoError(t, err)
	r = do(p2, http.MethodPost, readPath+"/scope", secret2, string(widen))
	require.Equal(t, http.StatusOK, r.Status, r.Body)

	require.Equal(t, http.StatusNotFound, do(p2, http.MethodPost, readPath+"/reject", secret2, `{}`).Status,
		"the agent's old secret cannot reject")
	r = do(p2, http.MethodPost, readPath+"/reject", newSecret, `{}`)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	require.Equal(t, websocket.StatusCode(channel.ErrLinkRefused), p2.Closed(wctx))
	require.Equal(t, []string{guardmodel.RejectViaLinkOrAgent, guardmodel.RejectViaScopeToken}, via())
}
