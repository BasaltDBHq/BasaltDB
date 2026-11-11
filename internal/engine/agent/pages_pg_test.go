package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// pageOrigin is the origin the test pages claim, as the engine's config
// would set it (http://localhost:<port>).
const pageOrigin = "http://localhost:8787"

// localPages is the engine's local pages for env's agent behind an
// httptest server: the person's browser.
type localPages struct {
	t   *testing.T
	srv *httptest.Server
}

func newLocalPages(t *testing.T, env agentEnv) localPages {
	t.Helper()
	site := pages.New(pageOrigin, slog.New(slog.DiscardHandler))
	site.Add(env.svc)
	srv := httptest.NewServer(site.Handler())
	t.Cleanup(srv.Close)
	return localPages{t: t, srv: srv}
}

// get reads path and decodes the JSON answer into out.
func (p localPages) get(path string, out any) int {
	p.t.Helper()
	resp, err := http.Get(p.srv.URL + path) //nolint:noctx // a test against a local httptest server
	require.NoError(p.t, err)
	defer resp.Body.Close()
	require.NoError(p.t, json.NewDecoder(resp.Body).Decode(out))
	return resp.StatusCode
}

// post sends body as the page does, from origin.
func (p localPages) post(path, origin string, body []byte, out any) int {
	p.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.srv.URL+path, bytes.NewReader(body))
	require.NoError(p.t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(p.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(p.t, err)
	if out != nil {
		require.NoError(p.t, json.Unmarshal(raw, out), string(raw))
	}
	return resp.StatusCode
}

// signApproval is the page: read the request for id, check it, and sign it
// with the person's passkey; it returns the response JSON the page posts.
func (p localPages) signApproval(id string, person *passkeytest.Authenticator) []byte {
	p.t.Helper()
	var req approval.Request
	require.Equal(p.t, http.StatusOK, p.get("/api/v1/approvals/"+id, &req))
	b, err := req.Check()
	require.NoError(p.t, err, "the served request passes the same checks as the long link")
	as, err := person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(p.t, err)
	body, err := json.Marshal(approval.NewResponse(b.ApprovalID, as))
	require.NoError(p.t, err)
	return body
}

type pageError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// holdWrite starts a run and returns the arguments of a write the guard
// holds (15 rows), with waitForApproval when wait is set.
func holdWrite(t *testing.T, h harness, wait *int) map[string]any {
	t.Helper()
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Close the stale leads"})
	require.False(t, isError, "%v", run)
	args := map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", 21, 35},
		"intent": "Leads 21 to 35 went cold", "runId": str(t, run["runId"]),
	}
	if wait != nil {
		args["waitForApproval"] = *wait
	}
	return args
}

func TestShortLinkApprovedThroughTheRelay(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	id := str(t, ap["approvalId"])
	require.Equal(t, pageOrigin+"/approve/"+id, ap["approvalUrl"], "the short link")
	msg := str(t, ap["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Held for your approval: Update 15 rows in public.leads. Approve: "+pageOrigin+"/approve/"+id+
		" (or run: basalt approve --agent bot --config /etc/basalt-test/engine.json --open "+id+"). Expires "), msg)
	require.True(t, strings.HasSuffix(msg, " UTC."), msg)
	require.Len(t, env.sent.sent, 1)
	require.Contains(t, env.sent.sent[0].ApprovalURL, "#1.", "Telegram keeps the long link")

	// The page itself is served for the short link.
	resp, err := http.Get(p.srv.URL + "/approve/" + id) //nolint:noctx // a test against a local httptest server
	require.NoError(t, err)
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(page), "../lib/approve.js")

	signed := p.signApproval(id, env.person)

	// The relay refuses a post from anywhere but the page's origin, and a
	// response for another approval.
	var perr pageError
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/approvals/"+id+"/approve", "http://evil.test", signed, &perr))
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/approvals/"+id+"/approve", "", signed, &perr))
	other := uuid.Must(uuid.NewV7()).String()
	require.Equal(t, http.StatusBadRequest, p.post("/api/v1/approvals/"+other+"/approve", pageOrigin, signed, &perr))
	require.Equal(t, "INVALID_ARGUMENT", perr.Code)

	var ok map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, signed, &ok))
	require.Equal(t, map[string]any{"approvalId": id, "status": "APPROVED"}, ok)

	// Signed: the page no longer offers it, and a replay is refused.
	require.Equal(t, http.StatusConflict, p.get("/api/v1/approvals/"+id, &perr))
	require.Equal(t, "APPROVAL_INVALID", perr.Code)
	require.Equal(t, http.StatusConflict, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, signed, &perr))

	// The agent repeats the write with approvalId: applied, no code relayed.
	args["approvalId"] = id
	body, isError = env.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, "closed", leadStatus(t, d, 21))
}

func TestPagesRefuseUnknownAndExpired(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	var perr pageError
	unknown := uuid.Must(uuid.NewV7()).String()
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/approvals/"+unknown, &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/reverts/"+unknown, &perr))
	require.Equal(t, http.StatusBadRequest, p.get("/api/v1/approvals/nope", &perr))

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	id := str(t, approvalOf(t, body)["approvalId"])
	d.Exec(t, `UPDATE basalt_meta.approvals SET expires_at = now() - interval '1 minute' WHERE approval_id = '`+id+`'`)
	require.Equal(t, http.StatusGone, p.get("/api/v1/approvals/"+id, &perr))
	require.Equal(t, "APPROVAL_EXPIRED", perr.Code)
}

func TestWaitingWriteAppliesWhenThePersonApproves(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	id := str(t, approvalOf(t, body)["approvalId"])

	// The agent repeats the write with approvalId and the default wait; the
	// person signs on the page a moment later.
	args["approvalId"] = id
	type answer struct {
		body    map[string]any
		isError bool
	}
	done := make(chan answer, 1)
	start := time.Now()
	go func() {
		b, e := env.h.call(t, "write", args)
		done <- answer{b, e}
	}()
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, p.signApproval(id, env.person), nil))
	got := <-done
	require.False(t, got.isError, "%v", got.body)
	require.Equal(t, "APPLIED", got.body["status"])
	require.Equal(t, json.Number("15"), got.body["rows"])
	require.Less(t, time.Since(start), 10*time.Second, "applied as soon as it was signed")
	require.Equal(t, "closed", leadStatus(t, d, 21))
}

func TestWaitingNewWriteTimesOutHeld(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)

	wait := 1
	args := holdWrite(t, env.h, &wait)
	start := time.Now()
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.GreaterOrEqual(t, time.Since(start), time.Second, "it waited")
	ap := approvalOf(t, body)
	require.Equal(t, pageOrigin+"/approve/"+str(t, ap["approvalId"]), ap["approvalUrl"])
	require.Equal(t, "open", leadStatus(t, d, 21), "nothing applied")
	require.Len(t, env.sent.sent, 1, "the person is told once")
}

func TestShortLinkRevertThroughTheRelay(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	env := agentHarnessFor(t, d, a, pageOrigin)
	p := newLocalPages(t, env)
	ctx := context.Background()

	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Mark leads won"}
	require.NoError(t, guard.StartRun(ctx, a.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 40 AND 45`))
	prep, err := guard.PrepareRevert(ctx, a.Conn, guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}, "Revert the run")
	require.NoError(t, err)
	id := prep.RevertID.String()

	var req revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, &req))
	b, err := req.Check()
	require.NoError(t, err)
	as, err := env.person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	signed, err := json.Marshal(revert.NewResponse(b.RevertID, as))
	require.NoError(t, err)

	var perr pageError
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/reverts/"+id+"/apply", "http://localhost:9999", signed, &perr))
	var out guard.AppliedRevert
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, signed, &out))
	require.Equal(t, 6, out.Rows)
	require.Equal(t, "open", leadStatus(t, d, 40))
	require.Equal(t, http.StatusConflict, p.get("/api/v1/reverts/"+id, &perr))
	require.Equal(t, "REVERT_INVALID", perr.Code)
}
