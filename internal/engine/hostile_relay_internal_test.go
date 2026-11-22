package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// heldItem is a held write: its approval id and the secret of its portal
// short link.
type heldItem struct {
	id     string
	secret string
	args   map[string]any
}

// hold has the agent hold a write of leads from to to.
func (e *relayEnv) hold(t *testing.T, from, to int) heldItem {
	t.Helper()
	return e.holdSQL(t, "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", []any{"closed", from, to})
}

// bumpSQL adds 1 to the score of leads $1 to $2: a write that is not
// idempotent, so applying it twice shows.
const bumpSQL = "UPDATE leads SET score = score + 1 WHERE id BETWEEN $1 AND $2"

// holdSQL has the agent hold the write sql with params.
func (e *relayEnv) holdSQL(t *testing.T, sql string, params []any) heldItem {
	t.Helper()
	run, isError := e.call(t, "run_start", map[string]any{"intent": "Close the stale leads"})
	require.False(t, isError, "%v", run)
	args := map[string]any{"sql": sql, "params": params, "intent": "They went cold", "runId": run["runId"]}
	held, isError := e.call(t, "write", args)
	require.True(t, isError)
	require.Equal(t, "APPROVAL_REQUIRED", held["code"], "%v", held)
	ap := held["approval"].(map[string]any)
	id, secret := portalLink(t, ap["approvalUrl"].(string), "approvals")
	args["approvalId"] = id
	return heldItem{id: id, secret: secret, args: args}
}

// session opens a Go page session on a short link's secret.
func (e *relayEnv) session(t *testing.T, ctx context.Context, secret string) (*pagetest.Page, error) {
	t.Helper()
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	return pagetest.Open(ctx, e.v.URL(), keys)
}

// readApproval reads a held write's request in a session.
func readApproval(t *testing.T, ctx context.Context, p *pagetest.Page, item heldItem) approval.Request {
	t.Helper()
	r, err := p.Do(ctx, http.MethodGet, "/api/v1/approvals/"+item.id, pagetest.Headers(item.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	var req approval.Request
	require.NoError(t, json.Unmarshal([]byte(r.Body), &req))
	_, err = req.Check()
	require.NoError(t, err)
	return req
}

// loopbackApproval reads a held write's request on the engine's own pages,
// for a test whose Vault breaks every session.
func (e *relayEnv) leadScore(t *testing.T, id int) int {
	t.Helper()
	var n int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT score FROM public.leads WHERE id = $1`, id).Scan(&n))
	return n
}

func (e *relayEnv) loopbackApproval(t *testing.T, item heldItem) approval.Request {
	t.Helper()
	site := pages.New(links.Portal, quietLog())
	site.Add(e.svc)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/approvals/"+item.id, nil)
	for k, v := range pagetest.Headers(item.secret) {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	site.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out approval.Request
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

// approveBody is the approve body for id with the assertion of signer over
// binding.
func approveBody(t *testing.T, signer *passkeytest.Authenticator, id string, binding string) string {
	t.Helper()
	as, err := signer.Sign(approval.Challenge(binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	b, err := json.Marshal(approval.NewResponse(uuid.MustParse(id), as))
	require.NoError(t, err)
	return string(b)
}

// Whoever holds a link without the person's passkey (the agent, a hostile
// Vault that saw the link) cannot approve or apply through the channel:
// Postgres refuses a signature made for another item and one made by any
// other key, and nothing is applied. No route registers a passkey or a box
// key, or serves a script, through a session.
func TestRelayChannelCannotSignWithoutThePerson(t *testing.T) {
	t.Parallel()
	e := newRelayEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, b := e.hold(t, 21, 35), e.hold(t, 36, 50)
	pa, err := e.session(t, ctx, a.secret)
	require.NoError(t, err)
	t.Cleanup(pa.Close)
	pb, err := e.session(t, ctx, b.secret)
	require.NoError(t, err)
	t.Cleanup(pb.Close)
	reqA, reqB := readApproval(t, ctx, pa, a), readApproval(t, ctx, pb, b)

	post := func(p *pagetest.Page, path, secret, body string) pagetest.Reply {
		t.Helper()
		r, err := p.Do(ctx, http.MethodPost, path, pagetest.PostHeaders(secret), body, 0)
		require.NoError(t, err)
		return r
	}
	// The person's signature for A, posted for B through B's session.
	asA, err := e.person.Sign(approval.Challenge(reqA.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	forB, err := json.Marshal(approval.NewResponse(uuid.MustParse(b.id), asA))
	require.NoError(t, err)
	r := post(pb, "/api/v1/approvals/"+b.id+"/approve", b.secret, string(forB))
	require.Equal(t, http.StatusConflict, r.Status, r.Body)
	require.Contains(t, r.Body, `"code":"APPROVAL_INVALID"`)

	// A key that is not the person's passkey, with the person's credential id.
	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = e.person.ID
	r = post(pb, "/api/v1/approvals/"+b.id+"/approve", b.secret, approveBody(t, forger, b.id, reqB.Binding))
	require.Equal(t, http.StatusConflict, r.Status, r.Body)
	require.Contains(t, r.Body, `"code":"APPROVAL_INVALID"`)
	require.Equal(t, "open", e.leadStatus(t, 36), "nothing applied")
	require.Equal(t, "open", e.leadStatus(t, 21))

	// A revert applied with another key's signature.
	revertID, revertSecret := e.prepareRevert(t, e.winRun(t, "61"))
	pr, err := e.session(t, ctx, revertSecret)
	require.NoError(t, err)
	t.Cleanup(pr.Close)
	rr, err := pr.Do(ctx, http.MethodGet, "/api/v1/reverts/"+revertID, pagetest.Headers(revertSecret), "", 0)
	require.NoError(t, err)
	var rreq revert.Request
	require.NoError(t, json.Unmarshal([]byte(rr.Body), &rreq))
	asR, err := forger.Sign(revert.Challenge(rreq.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	apply, err := json.Marshal(revert.NewResponse(uuid.MustParse(revertID), asR))
	require.NoError(t, err)
	r = post(pr, "/api/v1/reverts/"+revertID+"/apply", revertSecret, string(apply))
	require.Equal(t, http.StatusConflict, r.Status, r.Body)
	require.Contains(t, r.Body, `"code":"REVERT_INVALID"`)
	require.Equal(t, "won", e.leadStatus(t, 61), "nothing reverted")

	// Routes outside the pages API read as an unknown id.
	unknown, err := pb.Do(ctx, http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), pagetest.Headers(b.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, unknown.Status)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/passkeys"},
		{http.MethodPost, "/api/v1/passkeys/register"},
		{http.MethodPost, "/api/v1/engines/box-key"},
		{http.MethodGet, "/lib/codec.js"},
		{http.MethodGet, "/healthz"},
		{http.MethodPost, "/api/v1/approvals/" + b.id + "/links"},
		{http.MethodPut, "/api/v1/approvals/" + b.id},
		{http.MethodGet, "/api/v1/setups/" + uuid.Must(uuid.NewV7()).String()},
	} {
		headers := pagetest.Headers(b.secret)
		body := ""
		if route.method != http.MethodGet {
			headers, body = pagetest.PostHeaders(b.secret), "{}"
		}
		got, err := pb.Do(ctx, route.method, route.path, headers, body, 0)
		require.NoError(t, err)
		require.Equal(t, unknown, got, "%s %s", route.method, route.path)
	}
}

// relayTamper alters the session messages a fake Vault forwards, as edit
// says, with each message's index among those of its session and
// direction (message 1 and message 2 are index 0).
type relayTamper struct {
	mu   sync.Mutex
	seen map[[2]any]int
	edit func(m vaulttest.Message, n int) []vaulttest.Delivery
}

func (r *relayTamper) tamper(m vaulttest.Message) []vaulttest.Delivery {
	r.mu.Lock()
	m.Data = slices.Clone(m.Data)
	key := [2]any{m.Session.SID, m.Dir}
	n := r.seen[key]
	r.seen[key]++
	r.mu.Unlock()
	return r.edit(m, n)
}

func newTamperedRelayEnv(t *testing.T, edit func(m vaulttest.Message, n int) []vaulttest.Delivery) *relayEnv {
	t.Helper()
	r := &relayTamper{seen: map[[2]any]int{}, edit: edit}
	return newRelayEnvWith(t, vaulttest.Options{Tamper: r.tamper})
}

// A real approval through a Vault that drops, delays or duplicates the
// page's frames: the held write is applied once with the person's
// signature, or not at all, never twice, and the approval cannot be used
// again.
func TestRelayApprovalThroughAHostileVault(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		edit func(m vaulttest.Message, n int) []vaulttest.Delivery
		// postLands says the person's POST reaches the engine; maybe, that
		// the Vault may break the session before the engine runs it.
		postLands, maybe bool
		// wait is the waiting write's waitForApproval, in seconds: long
		// enough for a delayed signature, short for a dropped one.
		wait int
	}{
		"the signature's frame duplicated": {maybe: true, wait: 5, edit: func(m vaulttest.Message, n int) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToEngine && n == 2 {
				return []vaulttest.Delivery{vaulttest.Forward(m), vaulttest.Forward(m)}
			}
			return []vaulttest.Delivery{vaulttest.Forward(m)}
		}},
		"every frame delayed": {postLands: true, wait: 30, edit: func(m vaulttest.Message, _ int) []vaulttest.Delivery {
			time.Sleep(50 * time.Millisecond)
			return []vaulttest.Delivery{vaulttest.Forward(m)}
		}},
		"the signature's frame dropped": {postLands: false, wait: 3, edit: func(m vaulttest.Message, n int) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToEngine && n == 2 {
				return nil
			}
			return []vaulttest.Delivery{vaulttest.Forward(m)}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newTamperedRelayEnv(t, c.edit)
			// A write that is not idempotent: applied twice, lead 21 would
			// score 2.
			item := e.holdSQL(t, bumpSQL, []any{21, 35})
			wait := map[string]any{"waitForApproval": c.wait}
			for k, v := range item.args {
				wait[k] = v
			}
			waiting := e.later(t, "write", wait)

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			// What the person signs: this Vault may break every session, so
			// the test reads it on the engine's own pages.
			req := e.loopbackApproval(t, item)
			signer, err := e.session(t, ctx, item.secret)
			require.NoError(t, err)
			defer signer.Close()
			// Index 1 is a session's first frame: read the request again
			// first, so the POST is frame 2 (the one a drop removes).
			_, _ = signer.Do(ctx, http.MethodGet, "/api/v1/approvals/"+item.id, pagetest.Headers(item.secret), "", 0)
			postCtx, cancelPost := context.WithTimeout(ctx, 2*time.Second)
			defer cancelPost()
			_, _ = signer.Do(postCtx, http.MethodPost, "/api/v1/approvals/"+item.id+"/approve", pagetest.PostHeaders(item.secret),
				approveBody(t, e.person, item.id, req.Binding), 0)

			var body map[string]any
			select {
			case body = <-waiting:
			case <-time.After(time.Duration(c.wait+30) * time.Second):
				t.Fatal("the waiting write did not return")
			}
			applied := body["status"] == "APPLIED"
			switch {
			case c.postLands:
				require.True(t, applied, "%v", body)
			case !c.maybe:
				require.False(t, applied, "%v", body)
			}
			if !applied {
				require.Equal(t, "APPROVAL_REQUIRED", body["code"], "a clean failure: %v", body)
				require.Zero(t, e.leadScore(t, 21), "nothing applied without a signature the engine took")
				// The person signs again in a new session (its POST is frame
				// 1, which this Vault leaves alone): it must apply, once.
				retryCtx, cancelRetry := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancelRetry()
				p, err := e.session(t, retryCtx, item.secret)
				require.NoError(t, err)
				defer p.Close()
				r, err := p.Do(retryCtx, http.MethodPost, "/api/v1/approvals/"+item.id+"/approve", pagetest.PostHeaders(item.secret),
					approveBody(t, e.person, item.id, req.Binding), 0)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, r.Status, r.Body)
				done, isError := e.call(t, "write", item.args)
				require.False(t, isError, "%v", done)
				require.Equal(t, "APPLIED", done["status"], "%v", done)
			}
			// Applied exactly once: a second apply would score 2.
			require.Equal(t, 1, e.leadScore(t, 21))
			require.Equal(t, 1, e.leadScore(t, 35))
			again, isError := e.call(t, "write", item.args)
			require.True(t, isError)
			require.Equal(t, "APPROVAL_INVALID", again["code"], "the approval is single-use: %v", again)
			require.Equal(t, 1, e.leadScore(t, 21))
		})
	}
}
