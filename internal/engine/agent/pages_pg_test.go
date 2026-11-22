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
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
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

// get reads path with a link's secret, as the page does, and decodes the
// JSON answer into out.
func (p localPages) get(path, secret string, out any) int {
	p.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.srv.URL+path, nil)
	require.NoError(p.t, err)
	req.Header.Set(links.SecretHeader, secret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(p.t, err)
	defer resp.Body.Close()
	require.NoError(p.t, json.NewDecoder(resp.Body).Decode(out))
	return resp.StatusCode
}

// post sends body as the page does, from origin, with a link's secret
// ("" for none).
func (p localPages) post(path, origin, secret string, body []byte, out any) int {
	p.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.srv.URL+path, bytes.NewReader(body))
	require.NoError(p.t, err)
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if secret != "" {
		req.Header.Set(links.SecretHeader, secret)
	}
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
func (p localPages) signApproval(id, secret string, person *passkeytest.Authenticator) []byte {
	p.t.Helper()
	var req approval.Request
	require.Equal(p.t, http.StatusOK, p.get("/api/v1/approvals/"+id, secret, &req))
	b, err := req.Check()
	require.NoError(p.t, err, "the served request passes the same checks as the long link")
	as, err := person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(p.t, err)
	body, err := json.Marshal(approval.NewResponse(b.ApprovalID, as))
	require.NoError(p.t, err)
	return body
}

type pageError struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Reason        string         `json:"reason"`
	PersonMessage string         `json:"personMessage"`
	NextSteps     []mcp.NextStep `json:"nextSteps"`
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
	link := str(t, ap["approvalUrl"])
	secret := links.SecretOf(link)
	require.Len(t, secret, 22, "a 128-bit secret")
	require.Equal(t, pageOrigin+"/approvals/"+id+"#s="+secret, link, "the short link carries its secret in the fragment")
	msg := str(t, ap["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Held for your approval: Update 15 rows in public·leads.\nApprove it with your passkey here:\n\n"+link+
		"\n\nExpires "), msg)
	require.True(t, strings.HasSuffix(msg, " UTC."), msg)
	mcptest.Require(t, msg, mcptest.LinksOf(t, ap))
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: link}}, mcptest.LinksOf(t, ap))
	require.Len(t, env.sent.sent, 1)
	require.Contains(t, env.sent.sent[0].ApprovalURL, "#2.", "the notice keeps the long link")
	require.Equal(t, link, env.sent.sent[0].ShortURL, "the notice carries the short link")

	// The page itself is served for the short link.
	resp, err := http.Get(p.srv.URL + "/approvals/" + id) //nolint:noctx // a test against a local httptest server
	require.NoError(t, err)
	page, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(page), "../lib/approve.js")

	// The id alone opens nothing.
	var perr pageError
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/approvals/"+id, "", &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)

	signed := p.signApproval(id, secret, env.person)

	// The relay refuses a post without the secret, from anywhere but the
	// page's origin, and a response for another approval.
	require.Equal(t, http.StatusNotFound, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, "", signed, &perr))
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/approvals/"+id+"/approve", "http://evil.test", secret, signed, &perr))
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/approvals/"+id+"/approve", "", secret, signed, &perr))
	other := uuid.Must(uuid.NewV7()).String()
	require.Equal(t, http.StatusNotFound, p.post("/api/v1/approvals/"+other+"/approve", pageOrigin, secret, signed, &perr),
		"a secret opens only its own item")

	var ok map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, signed, &ok))
	require.Equal(t, id, ok["approvalId"])
	require.Equal(t, "APPROVED", ok["status"])
	require.Contains(t, ok, "receipt", "the relay answers with the engine's receipt")

	// Signed: the page no longer offers it, and a replay is refused.
	require.Equal(t, http.StatusConflict, p.get("/api/v1/approvals/"+id, secret, &perr))
	require.Equal(t, "APPROVAL_INVALID", perr.Code)
	require.Equal(t, http.StatusConflict, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, signed, &perr))

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
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/approvals/"+unknown, "x", &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, "LINK", perr.Reason)
	require.Contains(t, perr.PersonMessage, "Ask the agent for the link again")
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/reverts/"+unknown, "x", &perr))
	require.Equal(t, http.StatusBadRequest, p.get("/api/v1/approvals/nope", "x", &perr))

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	id, secret := str(t, ap["approvalId"]), links.SecretOf(str(t, ap["approvalUrl"]))
	d.Exec(t, `UPDATE basalt_meta.approvals SET expires_at = now() - interval '1 minute' WHERE approval_id = '`+id+`'`)
	perr = pageError{}
	require.Equal(t, http.StatusGone, p.get("/api/v1/approvals/"+id, secret, &perr), "the right secret on an expired write")
	require.Equal(t, "APPROVAL_EXPIRED", perr.Code)
	require.Contains(t, perr.PersonMessage, "expired before it was approved", "the page tells the person what happened")
	require.Empty(t, perr.NextSteps, "its steps are the agent's, not the page's")
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/approvals/"+id, "", &perr), "without it nothing is told")
}

func TestWaitingWriteAppliesWhenThePersonApproves(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	id, secret := str(t, ap["approvalId"]), links.SecretOf(str(t, ap["approvalUrl"]))

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
	env.waitPolling(t)
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, p.signApproval(id, secret, env.person), nil))
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
	require.True(t, strings.HasPrefix(str(t, ap["approvalUrl"]), pageOrigin+"/approvals/"+str(t, ap["approvalId"])+"#s="),
		"the hold's own answer, with the link it issued")
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

	// The revert's short link, as request_revert issues it.
	var perr pageError
	secret, err := env.svc.Links.Issue(prep.RevertID, time.Now().Add(time.Hour))
	require.NoError(t, err)

	var req revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &req))
	b, err := req.Check()
	require.NoError(t, err)
	as, err := env.person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	signed, err := json.Marshal(revert.NewResponse(b.RevertID, as))
	require.NoError(t, err)

	require.Equal(t, http.StatusNotFound, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, "", signed, &perr), "no secret, no relay")
	require.Equal(t, http.StatusForbidden, p.post("/api/v1/reverts/"+id+"/apply", "http://localhost:9999", secret, signed, &perr))
	var out guard.AppliedRevert
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, secret, signed, &out))
	require.Equal(t, 6, out.Rows)
	require.Equal(t, "open", leadStatus(t, d, 40))
	require.Equal(t, http.StatusConflict, p.get("/api/v1/reverts/"+id, secret, &perr))
	require.Equal(t, "REVERT_INVALID", perr.Code)
	require.Equal(t, "PLAN_FINISHED", perr.Reason)
}

// An expired revert's page error carries the person's message and their
// step: the command that prepares it again. The agent's steps stay out.
func TestRevertPageErrorCarriesThePersonsSteps(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)
	runID, _ := winLeads(t, env.h, "46, 47")
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	id, secret := str(t, req["revertId"]), links.SecretOf(str(t, req["revertUrl"]))
	expireRevert(t, env, id)

	var perr pageError
	require.Equal(t, http.StatusGone, p.get("/api/v1/reverts/"+id, secret, &perr))
	require.Equal(t, "REVERT_EXPIRED", perr.Code)
	require.Equal(t, "NOT_SIGNED", perr.Reason)
	require.Contains(t, perr.PersonMessage, "expired")
	require.Contains(t, perr.PersonMessage, "ask the agent to prepare it again")
	require.Empty(t, perr.NextSteps, "the agent prepares it again: the page has no step for the person")
}

func TestListPendingReissuesTheLink(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	id, first := str(t, ap["approvalId"]), links.SecretOf(str(t, ap["approvalUrl"]))
	var req approval.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/approvals/"+id, first, &req))

	// Listing touches no link: the one handed over keeps working.
	pending, isError := env.h.call(t, "list_pending", map[string]any{"runId": args["runId"]})
	require.False(t, isError, "%v", pending)
	list := items(t, pending)
	require.Len(t, list, 1)
	require.Contains(t, str(t, list[0]["approvalUrl"]), "#2.", "the long link, no new secret")
	require.Contains(t, list[0]["personMessage"], "Approve with the link you were given")
	require.Equal(t, http.StatusOK, p.get("/api/v1/approvals/"+id, first, &req))

	// The agent lost the link: reissueLink gives a working one.
	pending, isError = env.h.call(t, "list_pending", map[string]any{"runId": args["runId"], "reissueLink": true})
	require.False(t, isError, "%v", pending)
	list = items(t, pending)
	require.Len(t, list, 1)
	second := links.SecretOf(str(t, list[0]["approvalUrl"]))
	require.NotEmpty(t, second)
	require.NotEqual(t, first, second)
	require.Contains(t, list[0]["personMessage"], str(t, list[0]["approvalUrl"]))

	var perr pageError
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/approvals/"+id, first, &perr), "the re-issued link revokes the old one")
	require.Equal(t, http.StatusOK, p.get("/api/v1/approvals/"+id, second, &req))
}
