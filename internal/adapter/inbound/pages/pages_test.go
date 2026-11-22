package pages_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/httpserver"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/pages"

	// The app sets the agent's host at start; the stubs' agent.ToolError
	// reads it, so the tests run with the engine's own.
	_ "github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/web"
)

// stubAgent knows one approval; RelayApproval records what it relays.
// It issues links on the pages' secrets for the proof "good".
type stubAgent struct {
	known   uuid.UUID
	err     error
	relayed []approval.Response
	// revealed are the reveal requests the agent received.
	revealed []agent.RevealRequest
	secrets  *links.Secrets
	origin   string
	// receipt is what RelayApproval returns.
	receipt agent.Receipt
}

func (a *stubAgent) CheckLink(id uuid.UUID, secret string) bool { return a.secrets.Check(id, secret) }

func (a *stubAgent) PageFailure(err error) *mcp.ToolError { return agent.ToolError(err) }

func (a *stubAgent) ApprovalRequest(_ context.Context, id uuid.UUID) (approval.Request, error) {
	if id != a.known {
		return approval.Request{}, agent.ErrNotThisAgent
	}
	return approval.Request{ApprovalID: id, Binding: "{}", Lines: []string{}}, a.err
}

func (a *stubAgent) RelayApproval(_ context.Context, r approval.Response) (agent.Receipt, error) {
	if r.ApprovalID != a.known {
		return agent.Receipt{}, agent.ErrNotThisAgent
	}
	a.relayed = append(a.relayed, r)
	return a.receipt, a.err
}

func (a *stubAgent) RevertRequest(context.Context, uuid.UUID, string) (revert.Request, error) {
	return revert.Request{}, agent.ErrNotThisAgent
}

func (a *stubAgent) RescopeRevert(context.Context, uuid.UUID, string, agent.ScopeRequest) (agent.ScopeResponse, error) {
	return agent.ScopeResponse{}, agent.ErrNotThisAgent
}

func (a *stubAgent) CheckResetLink(uuid.UUID, string) bool { return false }

func (a *stubAgent) RejectRevert(context.Context, uuid.UUID, string, agent.RejectRequest) (agent.RejectResponse, error) {
	return agent.RejectResponse{}, agent.ErrNotThisAgent
}

func (a *stubAgent) RevealApproval(_ context.Context, id uuid.UUID, _ string, in agent.RevealRequest) (approval.RevealAnswer, error) {
	if id != a.known {
		return approval.RevealAnswer{}, agent.ErrNotThisAgent
	}
	if a.err != nil {
		return approval.RevealAnswer{}, a.err
	}
	a.revealed = append(a.revealed, in)
	return approval.RevealAnswer{Rows: []approval.RevealedRow{{Line: 1, Row: `[{"id": 9}, {"id": 9}, null]`}}}, nil
}

func (a *stubAgent) RevealRevert(context.Context, uuid.UUID, string, agent.RevealRequest) (approval.RevealAnswer, error) {
	return approval.RevealAnswer{}, agent.ErrNotThisAgent
}

func (a *stubAgent) RelayRevert(context.Context, revert.Response) (action.AppliedRevert, agent.Receipt, error) {
	return action.AppliedRevert{}, agent.Receipt{}, agent.ErrNotThisAgent
}

// site is the pages behind the real listener policy on a loopback port, as
// the engine serves them; origin is http://localhost:<that port>, the same
// origin a browser has through ssh -L <port>:localhost:<port>.
type site struct {
	base    string
	origin  string
	secrets *links.Secrets
}

// testAgent is an agent the test pages serve, told the pages' secrets and
// origin once they are known.
type testAgent interface {
	pages.Agent
	wire(secrets *links.Secrets, origin string)
}

func (a *stubAgent) wire(secrets *links.Secrets, origin string) {
	a.secrets, a.origin = secrets, origin
}

func serve(t *testing.T, agents ...*stubAgent) site {
	t.Helper()
	all := make([]testAgent, len(agents))
	for i, a := range agents {
		all[i] = a
	}
	return serveAgents(t, all...)
}

func serveAgents(t *testing.T, agents ...testAgent) site {
	t.Helper()
	// Bind first to learn the port, which is part of the page origin.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	origin := "http://localhost:" + port

	secrets := links.NewSecrets(time.Now, rand.Reader)
	p := pages.New(origin, slog.New(slog.DiscardHandler))
	for _, a := range agents {
		a.wire(secrets, origin)
		p.Add(a)
	}
	ln, h, err := httpserver.Listen(httpserver.Options{}, "approval pages", addr, p.Handler())
	require.NoError(t, err)
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 0}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return site{base: "http://" + addr, origin: origin, secrets: secrets}
}

// do sends one request; secret, when given, goes in the link-secret
// header as the page sends it.
func (s site) do(t *testing.T, method, path, host, origin, contentType, body string, secret ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, s.base+path, strings.NewReader(body))
	require.NoError(t, err)
	for _, v := range secret {
		req.Header.Set(links.SecretHeader, v)
	}
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func TestPagesServeTheEmbeddedFiles(t *testing.T) {
	t.Parallel()
	s := serve(t)
	host := strings.TrimPrefix(s.origin, "http://")
	id := uuid.Must(uuid.NewV7()).String()
	for path, want := range map[string]string{
		"/healthz":               "ok",
		"/approvals/" + id:       "../lib/approve.js",
		"/reverts/" + id:         "../lib/revert.js",
		"/plugins/" + id:         "../lib/plugin.js",
		"/passkeys/register":     "../lib/register.js",
		"/passkeys/check":        "404",
		"/passkeys/forget":       "404",
		"/passkeys/":             "404",
		"/lib/approve.js":        "pageId",
		"/lib/local.js":          "RelayError",
		"/lib/transport.js":      "sameOriginSession",
		"/style.css":             "{",
		"/fonts/Geist-400.woff2": "wOF2",
		"/fonts/OFL.txt":         "SIL Open Font License",
		"/approvals/" + id[1:]:   "404",
	} {
		status, body := s.do(t, http.MethodGet, path, host, "", "", "")
		if want == "404" {
			require.Equal(t, http.StatusNotFound, status, path)
			continue
		}
		require.Equal(t, http.StatusOK, status, path)
		require.Contains(t, body, want, path)
	}
	// The old paths and anything else under web/ are not served.
	for _, path := range []string{
		"/", "/lib/", "/lib/codec.test.mjs", "/embed.go", "/approve/", "/approve/" + id,
		"/revert/" + id, "/register/", "/approvals/", "/approve/index.html",
		"/fonts/", "/fonts/missing.woff2", "/fonts/Geist-400.ttf",
	} {
		status, _ := s.do(t, http.MethodGet, path, host, "", "", "")
		require.Equal(t, http.StatusNotFound, status, "%s: no listings, no tests, no sources", path)
	}
}

func TestPagesHostCheck(t *testing.T) {
	t.Parallel()
	s := serve(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.base, "http://"))
	for _, host := range []string{"localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port} {
		status, _ := s.do(t, http.MethodGet, "/healthz", host, "", "", "")
		require.Equal(t, http.StatusOK, status, host)
	}
	// A DNS-rebinding page reaches the loopback port under its own name.
	status, _ := s.do(t, http.MethodGet, "/healthz", "evil.test:"+port, "", "", "")
	require.Equal(t, http.StatusBadRequest, status)
}

func TestPagesRelayChecks(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &stubAgent{known: id}
	s := serve(t, a)
	host := strings.TrimPrefix(s.origin, "http://")
	path := "/api/v1/approvals/" + id.String() + "/approve"
	body := fmt.Sprintf(`{"approvalId":%q,"credentialId":"AQ","authenticatorData":"Ag","clientDataJson":"Aw","signature":"BA"}`, id)
	secret, err := s.secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)

	status, out := s.do(t, http.MethodPost, path, host, "", "application/json", body, secret)
	require.Equal(t, http.StatusForbidden, status, "no Origin: %s", out)
	status, _ = s.do(t, http.MethodPost, path, host, "http://localhost:1", "application/json", body, secret)
	require.Equal(t, http.StatusForbidden, status, "another port")
	status, _ = s.do(t, http.MethodPost, path, host, s.origin, "text/plain", body, secret)
	require.Equal(t, http.StatusUnsupportedMediaType, status, "a form post")
	status, _ = s.do(t, http.MethodPost, path, host, s.origin, "application/json", `{"approvalId":"`+strings.Repeat("x", 20<<10)+`"}`, secret)
	require.Equal(t, http.StatusRequestEntityTooLarge, status)
	status, out = s.do(t, http.MethodPost, path, host, s.origin, "application/json", `{"approvalId":1}`, secret)
	require.Equal(t, http.StatusBadRequest, status, out)
	require.Empty(t, a.relayed)

	// The page's own post: forwarded to localhost, the browser's Origin
	// is http://localhost:<port>, the page origin.
	// The answer carries the engine's receipt of the signature.
	a.receipt = agent.Receipt{Token: "basalt-receipt.1.cA.cw", Line: "Approved: ..."}
	status, out = s.do(t, http.MethodPost, path, host, s.origin, "application/json", body, secret)
	require.Equal(t, http.StatusOK, status, out)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"status":"APPROVED","receipt":"basalt-receipt.1.cA.cw"}`, id), out)
	require.Len(t, a.relayed, 1)

	// Without a usable engine key the approval still goes through, and the
	// answer says why there is no receipt.
	a.receipt = agent.Receipt{Missing: agent.NoReceiptKeyError, Line: "No receipt: ..."}
	status, out = s.do(t, http.MethodPost, path, host, s.origin, "application/json", body, secret)
	require.Equal(t, http.StatusOK, status, out)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"status":"APPROVED","noReceipt":"KEY_ERROR"}`, id), out)
	require.Len(t, a.relayed, 2)
	a.relayed = a.relayed[:1]

	// Errors keep the contract's code and map to a status.
	a.err = &mcp.ToolError{Code: agent.CodeApprovalExpired, Message: "this approval expired"}
	status, out = s.do(t, http.MethodGet, "/api/v1/approvals/"+id.String(), host, "", "", "", secret)
	require.Equal(t, http.StatusGone, status)
	require.JSONEq(t, `{"code":"APPROVAL_EXPIRED","message":"this approval expired"}`, out)
	status, out = s.do(t, http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), host, "", "", "", secret)
	require.Equal(t, http.StatusNotFound, status, out)
}

// An unknown link tells the person what to do: ask the agent again. The
// error carries the person's message and only the person's steps.
func TestPagesUnknownLinkCarriesThePersonsMessageAndSteps(t *testing.T) {
	t.Parallel()
	s := serve(t, &stubAgent{known: uuid.Must(uuid.NewV7())})
	host := strings.TrimPrefix(s.origin, "http://")
	status, out := s.do(t, http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), host, "", "", "")
	require.Equal(t, http.StatusNotFound, status)
	var body struct {
		Code          string         `json:"code"`
		Reason        string         `json:"reason"`
		PersonMessage string         `json:"personMessage"`
		NextSteps     []mcp.NextStep `json:"nextSteps"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &body))
	require.Equal(t, "NOT_FOUND", body.Code)
	require.Equal(t, "LINK", body.Reason)
	require.Contains(t, body.PersonMessage, "Ask the agent for the link again")
	require.Len(t, body.NextSteps, 1)
	require.Equal(t, mcp.ActorPerson, body.NextSteps[0].Actor)
	require.Equal(t, mcp.ActionTellAgent, body.NextSteps[0].Action)
}

// TestRedirectsMatchRoutes: the portal's web/_redirects rewrites exactly the
// paths the local pages server serves, to the same files.
func TestRedirectsMatchRoutes(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../../web/_redirects")
	require.NoError(t, err)
	got := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		require.Len(t, f, 3, line)
		require.Equal(t, "200", f[2], "a rewrite, not a redirect: %s", line)
		require.NotContains(t, got, f[0], "duplicate rule")
		got[f[0]] = f[1]
	}
	want := map[string]string{}
	for _, r := range web.PortalPages() {
		src := r.Path
		if r.ID {
			src += "*"
		}
		want[src] = "/" + strings.TrimSuffix(r.File, "index.html")
		_, err := os.Stat("../../../../web/" + r.File)
		require.NoError(t, err)
	}
	require.Equal(t, want, got)
}
