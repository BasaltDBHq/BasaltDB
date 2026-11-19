package pages_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// pluginAgent is a stubAgent that also serves plugin approvals: it knows
// one plugin approval (plugin), which it opened, and stands in for the
// guard's submit_plugin_approval, recording what it relays.
type pluginAgent struct {
	stubAgent
	plugin    uuid.UUID
	pluginErr error
	submitted []approval.PluginResponse
	at        time.Time
}

var _ pages.PluginApprovals = (*pluginAgent)(nil)

const (
	pluginBinding  = `{"kind": "PLUGIN", "name": "local-ner"}`
	pluginSettings = `{"timeoutMs": 300}`
)

func (a *pluginAgent) PluginApprovalRequest(_ context.Context, id uuid.UUID) (approval.PluginRequest, error) {
	if id != a.plugin {
		return approval.PluginRequest{}, agent.ErrNotThisAgent
	}
	return approval.PluginRequest{ApprovalID: id, Binding: pluginBinding, Settings: pluginSettings}, a.pluginErr
}

func (a *pluginAgent) RelayPluginApproval(_ context.Context, r approval.PluginResponse) (time.Time, error) {
	if r.ApprovalID != a.plugin {
		return time.Time{}, agent.ErrNotThisAgent
	}
	if a.pluginErr != nil {
		return time.Time{}, a.pluginErr
	}
	a.submitted = append(a.submitted, r)
	return a.at, nil
}

func (a *pluginAgent) IssuePluginLink(_ context.Context, id uuid.UUID, proof string) (string, error) {
	if id != a.plugin || proof != links.IssueProof(pluginBinding) {
		return "", agent.ErrNotThisAgent
	}
	secret, err := a.secrets.Issue(id, time.Now().Add(time.Hour))
	return links.WithSecret(links.Plugin(a.origin, id), secret), err
}

func pluginResponseBody(id uuid.UUID) string {
	return fmt.Sprintf(`{"approvalId":%q,"credentialId":"AQ","authenticatorData":"Ag","clientDataJson":"Aw","signature":"BA"}`, id)
}

// TestRelayPluginApproval: POST /api/v1/plugins/{id}/approve takes the
// link's secret, then the approval relay's origin, content type and size
// checks, and a body that is this approval's signed response, before
// anything reaches the guard. The answer is the contract's: no receipt.
func TestRelayPluginApproval(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	approvedAt := time.Date(2026, 11, 19, 10, 0, 0, 123456000, time.FixedZone("x", 3600))
	a := &pluginAgent{plugin: id, at: approvedAt}
	p := serveAgents(t, a)
	host := strings.TrimPrefix(p.origin, "http://")
	path := "/api/v1/plugins/" + id.String() + "/approve"
	body := pluginResponseBody(id)
	secret, err := p.secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)

	status, _ := p.do(t, http.MethodPost, path, host, p.origin, "application/json", body)
	require.Equal(t, http.StatusNotFound, status, "no link secret reads as an unknown id")
	status, _ = p.do(t, http.MethodPost, path, host, p.origin, "application/json", body, "wrong")
	require.Equal(t, http.StatusNotFound, status, "a wrong link secret reads as an unknown id")
	status, out := p.do(t, http.MethodPost, path, host, "", "application/json", body, secret)
	require.Equal(t, http.StatusForbidden, status, "no Origin: %s", out)
	status, _ = p.do(t, http.MethodPost, path, host, "http://localhost:1", "application/json", body, secret)
	require.Equal(t, http.StatusForbidden, status, "another port")
	status, _ = p.do(t, http.MethodPost, path, host, p.origin, "text/plain", body, secret)
	require.Equal(t, http.StatusUnsupportedMediaType, status, "a form post")
	status, _ = p.do(t, http.MethodPost, path, host, p.origin, "application/json", `{"approvalId":"`+strings.Repeat("x", 20<<10)+`"}`, secret)
	require.Equal(t, http.StatusRequestEntityTooLarge, status)
	for name, bad := range map[string]string{
		"not a response":     `{"approvalId":1}`,
		"another approval":   pluginResponseBody(uuid.Must(uuid.NewV7())),
		"an unknown key":     strings.Replace(body, `{`, `{"receipt":"x",`, 1),
		"no signature":       strings.Replace(body, `,"signature":"BA"`, "", 1),
		"an approval's code": "basalt-approval.1.e30",
	} {
		status, out := p.do(t, http.MethodPost, path, host, p.origin, "application/json", bad, secret)
		require.Equal(t, http.StatusBadRequest, status, name+": "+out)
	}
	require.Empty(t, a.submitted, "nothing reached the guard")

	// The page's own post.
	status, out = p.do(t, http.MethodPost, path, host, p.origin, "application/json", body, secret)
	require.Equal(t, http.StatusOK, status, out)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"status":"APPROVED","approvedAt":"2026-11-19T09:00:00.123456Z"}`, id), out)
	require.Len(t, a.submitted, 1)
	require.Equal(t, id, a.submitted[0].ApprovalID)
	require.Equal(t, []byte{4}, []byte(a.submitted[0].Signature))

	// The guard's refusals keep the contract's codes and statuses.
	for _, c := range []struct {
		err    *mcp.ToolError
		status int
	}{
		{&mcp.ToolError{Code: agent.CodeApprovalExpired, Message: "this plugin approval expired"}, http.StatusGone},
		{&mcp.ToolError{Code: agent.CodeApprovalInvalid, Message: "already signed"}, http.StatusConflict},
		{&mcp.ToolError{Code: agent.CodeUnavailable, Reason: "GUARD_OUTDATED", Message: "the guard is older than schema version 5"}, http.StatusServiceUnavailable},
	} {
		a.pluginErr = c.err
		status, out := p.do(t, http.MethodPost, path, host, p.origin, "application/json", body, secret)
		require.Equal(t, c.status, status, out)
		var got struct {
			Code string `json:"code"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &got))
		require.Equal(t, c.err.Code, got.Code)
	}
	require.Len(t, a.submitted, 1)
}

// GET /api/v1/plugins/{id}: the request for the page holding the link's
// secret, as the agent that opened the approval reads it.
func TestPluginApprovalRequestRoute(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &pluginAgent{plugin: id}
	p := serveAgents(t, a)
	host := strings.TrimPrefix(p.origin, "http://")
	path := "/api/v1/plugins/" + id.String()
	secret, err := p.secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)

	status, _ := p.do(t, http.MethodGet, path, host, "", "", "")
	require.Equal(t, http.StatusNotFound, status, "the id alone is not enough")
	status, out := p.do(t, http.MethodGet, path, host, "", "", "", secret)
	require.Equal(t, http.StatusOK, status, out)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"binding":%q,"settings":%q}`, id, pluginBinding, pluginSettings), out)

	a.pluginErr = &mcp.ToolError{Code: agent.CodeApprovalExpired, Message: "expired"}
	status, _ = p.do(t, http.MethodGet, path, host, "", "", "", secret)
	require.Equal(t, http.StatusGone, status)

	// An agent that serves no plugin approvals does not know the id, even
	// with a live secret for it.
	other := uuid.Must(uuid.NewV7())
	plain := serve(t, &stubAgent{known: other})
	otherSecret, err := plain.secrets.Issue(other, time.Now().Add(time.Hour))
	require.NoError(t, err)
	status, _ = plain.do(t, http.MethodGet, "/api/v1/plugins/"+other.String(), strings.TrimPrefix(plain.origin, "http://"), "", "", "", otherSecret)
	require.Equal(t, http.StatusNotFound, status)
}

// POST /api/v1/plugins/{id}/links issues a short link to a caller with
// proof of the binding text, as for held writes.
func TestPluginLinkRoute(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &pluginAgent{plugin: id}
	p := serveAgents(t, a)
	host := strings.TrimPrefix(p.origin, "http://")
	path := "/api/v1/plugins/" + id.String() + "/links"
	proof := fmt.Sprintf(`{"proof":%q}`, links.IssueProof(pluginBinding))

	status, out := p.do(t, http.MethodPost, path, host, "", "application/json", proof)
	require.Equal(t, http.StatusOK, status, out)
	var got struct {
		URL string `json:"url"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.True(t, strings.HasPrefix(got.URL, p.origin+"/plugins/"+id.String()+"#s="), got.URL)
	require.True(t, p.secrets.Check(id, strings.SplitN(got.URL, "#s=", 2)[1]))

	status, _ = p.do(t, http.MethodPost, path, host, "", "application/json", `{"proof":"wrong"}`)
	require.Equal(t, http.StatusNotFound, status, "a wrong proof reads as an unknown id")
	status, _ = p.do(t, http.MethodPost, path, host, "https://evil.example", "application/json", proof)
	require.Equal(t, http.StatusForbidden, status)
	status, _ = p.do(t, http.MethodPost, path, host, "", "text/plain", proof)
	require.Equal(t, http.StatusUnsupportedMediaType, status)
}

// The page itself is served at /plugins/<id>, and nothing else under it.
func TestPluginPageServed(t *testing.T) {
	t.Parallel()
	p := serveAgents(t, &pluginAgent{})
	host := strings.TrimPrefix(p.origin, "http://")
	id := uuid.Must(uuid.NewV7()).String()
	status, out := p.do(t, http.MethodGet, "/plugins/"+id, host, "", "", "")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, out, "../lib/plugin.js")
	for _, path := range []string{"/plugins/", "/plugins/" + id[1:], "/plugin/index.html", "/plugin/" + id} {
		status, _ := p.do(t, http.MethodGet, path, host, "", "", "")
		require.Equal(t, http.StatusNotFound, status, path)
	}
}

// In a Vault session the request and the relay are served for the
// session's own approval; the links route is not.
func TestPluginRoutesInASession(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	const origin = links.Portal
	secrets := links.NewSecrets(time.Now, rand.Reader)
	a := &pluginAgent{plugin: id, at: time.Now()}
	a.secrets, a.origin = secrets, origin
	srv := pages.New(origin, slog.New(slog.DiscardHandler))
	srv.Add(a)
	secret, err := secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	link := vault.SessionLink{Token: keys.Token, Item: id}
	headers := map[string]string{links.SecretHeader: secret, "origin": origin}

	got := srv.Dispatch(context.Background(), link, vault.Request{Method: http.MethodGet, Path: "/api/v1/plugins/" + id.String(), Headers: headers})
	require.Equal(t, http.StatusOK, got.Status, string(got.Body))
	require.Contains(t, string(got.Body), `"settings"`)

	post := map[string]string{links.SecretHeader: secret, "origin": origin, "content-type": "application/json"}
	got = srv.Dispatch(context.Background(), link, vault.Request{
		Method: http.MethodPost, Path: "/api/v1/plugins/" + id.String() + "/approve", Headers: post, Body: []byte(pluginResponseBody(id)),
	})
	require.Equal(t, http.StatusOK, got.Status, string(got.Body))
	require.Len(t, a.submitted, 1)

	got = srv.Dispatch(context.Background(), link, vault.Request{
		Method: http.MethodPost, Path: "/api/v1/plugins/" + id.String() + "/links", Headers: post,
		Body: []byte(fmt.Sprintf(`{"proof":%q}`, links.IssueProof(pluginBinding))),
	})
	require.Equal(t, http.StatusNotFound, got.Status, "a session never issues links")

	// Another approval than the session's own is unknown.
	other := uuid.Must(uuid.NewV7())
	got = srv.Dispatch(context.Background(), link, vault.Request{Method: http.MethodGet, Path: "/api/v1/plugins/" + other.String(), Headers: headers})
	require.Equal(t, http.StatusNotFound, got.Status)
}
