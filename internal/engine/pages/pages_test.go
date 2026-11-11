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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// stubAgent knows one approval; RelayApproval records what it relays.
// It issues links on the pages' secrets for the proof "good".
type stubAgent struct {
	known   uuid.UUID
	err     error
	relayed []approval.Response
	secrets *links.Secrets
	origin  string
}

func (a *stubAgent) IssueApprovalLink(_ context.Context, id uuid.UUID, proof string) (string, error) {
	if id != a.known || proof != "good" {
		return "", agent.ErrNotThisAgent
	}
	secret, err := a.secrets.Issue(id, time.Now().Add(time.Hour))
	return links.WithSecret(links.Approval(a.origin, id), secret), err
}

func (a *stubAgent) IssueRevertLink(context.Context, uuid.UUID, string) (string, error) {
	return "", agent.ErrNotThisAgent
}

func (a *stubAgent) CheckLink(id uuid.UUID, secret string) bool { return a.secrets.Check(id, secret) }

func (a *stubAgent) ApprovalRequest(_ context.Context, id uuid.UUID) (approval.Request, error) {
	if id != a.known {
		return approval.Request{}, agent.ErrNotThisAgent
	}
	return approval.Request{ApprovalID: id, Binding: "{}", Lines: []string{}}, a.err
}

func (a *stubAgent) RelayApproval(_ context.Context, r approval.Response) error {
	if r.ApprovalID != a.known {
		return agent.ErrNotThisAgent
	}
	a.relayed = append(a.relayed, r)
	return a.err
}

func (a *stubAgent) RevertRequest(context.Context, uuid.UUID) (revert.Request, error) {
	return revert.Request{}, agent.ErrNotThisAgent
}

func (a *stubAgent) RelayRevert(context.Context, revert.Response) (guard.AppliedRevert, error) {
	return guard.AppliedRevert{}, agent.ErrNotThisAgent
}

// site is the pages behind the real listener policy on a loopback port, as
// the engine serves them; origin is http://localhost:<that port>, the same
// origin a browser has through ssh -L <port>:localhost:<port>.
type site struct {
	base    string
	origin  string
	secrets *links.Secrets
}

func serve(t *testing.T, agents ...*stubAgent) site {
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
		a.secrets, a.origin = secrets, origin
		p.Add(a)
	}
	ln, h, err := server.Listen(server.Options{}, "approval pages", addr, p.Handler())
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
		"/healthz":             "ok",
		"/approvals/" + id:     "../lib/approve.js",
		"/reverts/" + id:       "../lib/revert.js",
		"/passkeys/register":   "../lib/register.js",
		"/passkeys/check":      "../lib/passkeys.js",
		"/passkeys/forget":     "../lib/passkeys.js",
		"/lib/manage.js":       "signalUnknownCredential",
		"/passkeys/":           "404",
		"/lib/approve.js":      "pageId",
		"/lib/local.js":        "RelayError",
		"/style.css":           "{",
		"/approvals/" + id[1:]: "404",
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
	for _, path := range []string{"/", "/lib/", "/lib/codec.test.mjs", "/embed.go", "/approve/", "/approve/" + id,
		"/revert/" + id, "/register/", "/approvals/", "/approve/index.html"} {
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

	// The page's own post: through the tunnel the browser's Origin is
	// http://localhost:<port>, the page origin.
	status, out = s.do(t, http.MethodPost, path, host, s.origin, "application/json", body, secret)
	require.Equal(t, http.StatusOK, status, out)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"status":"APPROVED"}`, id), out)
	require.Len(t, a.relayed, 1)

	// Errors keep the contract's code and map to a status.
	a.err = &mcp.ToolError{Code: agent.CodeApprovalExpired, Message: "this approval expired"}
	status, out = s.do(t, http.MethodGet, "/api/v1/approvals/"+id.String(), host, "", "", "", secret)
	require.Equal(t, http.StatusGone, status)
	require.JSONEq(t, `{"code":"APPROVAL_EXPIRED","message":"this approval expired"}`, out)
	status, out = s.do(t, http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), host, "", "", "", secret)
	require.Equal(t, http.StatusNotFound, status, out)
}

func TestPagesRequireTheLinkSecret(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &stubAgent{known: id}
	s := serve(t, a)
	host := strings.TrimPrefix(s.origin, "http://")
	get := "/api/v1/approvals/" + id.String()
	post := get + "/approve"
	body := fmt.Sprintf(`{"approvalId":%q,"credentialId":"AQ","authenticatorData":"Ag","clientDataJson":"Aw","signature":"BA"}`, id)

	// Unknown id: the answer every refusal below must match exactly.
	_, unknown := s.do(t, http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), host, "", "", "")

	secret, err := s.secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)
	wrong := []byte(secret)
	wrong[0] ^= 1
	for name, sent := range map[string][]string{"no secret": nil, "empty": {""}, "wrong": {string(wrong)}} {
		status, out := s.do(t, http.MethodGet, get, host, "", "", "", sent...)
		require.Equal(t, http.StatusNotFound, status, name)
		require.Equal(t, unknown, out, "%s: told apart from an unknown id by nothing", name)
		status, out = s.do(t, http.MethodPost, post, host, s.origin, "application/json", body, sent...)
		require.Equal(t, http.StatusNotFound, status, name)
		require.Equal(t, unknown, out, name)
	}
	require.Empty(t, a.relayed, "the relay refuses without the secret")

	status, out := s.do(t, http.MethodGet, get, host, "", "", "", secret)
	require.Equal(t, http.StatusOK, status, out)

	// The CLI's link request: proof of the binding, no Origin.
	issuePath := "/api/v1/approvals/" + id.String() + "/links"
	status, out = s.do(t, http.MethodPost, issuePath, host, "", "application/json", `{"proof":"bad"}`)
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, unknown, out, "a wrong proof is answered as an unknown id")
	status, out = s.do(t, http.MethodPost, issuePath, host, "http://evil.test", "application/json", `{"proof":"good"}`)
	require.Equal(t, http.StatusForbidden, status, out)
	status, out = s.do(t, http.MethodPost, issuePath, host, "", "application/json", `{"proof":"good"}`)
	require.Equal(t, http.StatusOK, status, out)
	var issued struct{ URL string }
	require.NoError(t, json.Unmarshal([]byte(out), &issued))
	require.True(t, strings.HasPrefix(issued.URL, s.origin+"/approvals/"+id.String()+"#s="), issued.URL)
	fresh := issued.URL[strings.LastIndex(issued.URL, "=")+1:]

	// The new link revoked the earlier one.
	status, _ = s.do(t, http.MethodGet, get, host, "", "", "", secret)
	require.Equal(t, http.StatusNotFound, status, "the re-issued link revokes the old one")
	status, _ = s.do(t, http.MethodGet, get, host, "", "", "", fresh)
	require.Equal(t, http.StatusOK, status)
}
