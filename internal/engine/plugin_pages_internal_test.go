package engine

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/store/postgres"
)

// pluginApprovalDetail is the detail of a local wire.detect entry in same-user
// mode with no known signer, for the given agent roles.
func pluginApprovalDetail(version string, agents ...string) guard.PluginApprovalDetail {
	return guard.PluginApprovalDetail{
		Agents: agents, Name: "local-ner", Instance: "client_x", Version: version,
		ManifestSHA256: strings.Repeat("a1", 32), Hooks: []string{"wire.detect"}, Roles: []string{"VALUE"},
		Egress: []string{}, Endpoint: guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
		Signer:    guard.PluginSignerUnknown,
	}
}

// pluginPages is the engine's local pages serving three agents of two
// databases on their real guards: helper and bot share one database, other
// has its own. Every service is the engine's own (pgAgent).
type pluginPages struct {
	t      *testing.T
	srv    *pages.Server
	origin string
	// offset moves the services' clock forward.
	offset atomic.Int64
}

func (p *pluginPages) do(method, path string, headers map[string]string, body string) (int, map[string]any) {
	p.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	p.srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	require.NoError(p.t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return rec.Code, out
}

// issue asks for a short link as basalt plugin add does: no Origin.
func (p *pluginPages) issue(id uuid.UUID, binding string) (int, map[string]any) {
	p.t.Helper()
	body, err := json.Marshal(map[string]string{"proof": links.IssueProof(binding)})
	require.NoError(p.t, err)
	return p.do(http.MethodPost, "/api/v1/plugins/"+id.String()+"/links", map[string]string{"Content-Type": "application/json"}, string(body))
}

func (p *pluginPages) get(id uuid.UUID, secret string) (int, map[string]any) {
	p.t.Helper()
	return p.do(http.MethodGet, "/api/v1/plugins/"+id.String(), map[string]string{links.SecretHeader: secret}, "")
}

func (p *pluginPages) approve(id uuid.UUID, secret string, resp approval.PluginApprovalResponse) (int, map[string]any) {
	p.t.Helper()
	body, err := json.Marshal(resp)
	require.NoError(p.t, err)
	return p.do(http.MethodPost, "/api/v1/plugins/"+id.String()+"/approve", map[string]string{
		"Origin": p.origin, "Content-Type": "application/json", links.SecretHeader: secret,
	}, string(body))
}

// secretOf is the secret of a short link the routes issued for id.
func (p *pluginPages) secretOf(id uuid.UUID, out map[string]any) string {
	p.t.Helper()
	url, _ := out["url"].(string)
	secret, ok := strings.CutPrefix(url, p.origin+"/plugins/"+id.String()+"#s=")
	require.True(p.t, ok, "the short link is the plugin page on the local origin: %q", url)
	return secret
}

// TestPluginRoutesAgainstGuard runs the plugin approval page's three routes
// through the engine's agent services against real guards: a short link is
// issued only to proof of the binding text, the page reads the request and
// relays the person's signature, and Postgres records PLUGIN_APPROVED for
// every agent the approval names. A named agent that did not open it, and
// an agent of another database, never answer for it.
func TestPluginRoutesAgainstGuard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	leads := []string{"public.leads"}
	bot, helper := d.NewAgent(t, "bot", leads, nil), d.NewAgent(t, "helper", leads, nil)
	elsewhere := guardtest.New(t).WithDemo(t)
	other := elsewhere.NewAgent(t, "other", leads, nil)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))

	p := &pluginPages{t: t, origin: "http://localhost:8787"}
	p.srv = pages.New(p.origin, quietLog())
	clock := func() time.Time { return time.Now().Add(time.Duration(p.offset.Load())) }
	// The agents that cannot answer are added first, so a lookup that
	// stopped at them would never reach the opener.
	for _, a := range []*guardtest.Agent{helper, other, bot} {
		pg := newPGAgent(t, a.URL, 2)
		p.srv.Add(pg.service(func(dp *agent.Deps) {
			dp.Name, dp.Now = strings.TrimPrefix(a.Role, d.Names.Prefix+"_agent_"), clock
			dp.PagesOrigin, dp.Links = p.origin, links.NewSecrets(time.Now, rand.Reader)
			dp.PluginApprovals = pg.store
		}))
	}

	timeout := 300
	opened, err := guard.OpenPluginApproval(ctx, bot.Conn, pluginApprovalDetail("0.3.1", bot.Role, helper.Role),
		guard.PluginSettings{TimeoutMs: &timeout})
	require.NoError(t, err)

	// No link without proof of the binding text: answered as an unknown id.
	status, out := p.issue(opened.ID, opened.BindingText+" ")
	require.Equal(t, http.StatusNotFound, status, out)
	require.Equal(t, "NOT_FOUND", out["code"])
	status, out = p.issue(uuid.Must(uuid.NewV7()), opened.BindingText)
	require.Equal(t, http.StatusNotFound, status, out)

	status, out = p.issue(opened.ID, opened.BindingText)
	require.Equal(t, http.StatusOK, status, out)
	secret := p.secretOf(opened.ID, out)

	// No request without the link's secret.
	status, _ = p.get(opened.ID, "")
	require.Equal(t, http.StatusNotFound, status)
	status, out = p.get(opened.ID, secret)
	require.Equal(t, http.StatusOK, status, out)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	var req approval.PluginRequest
	require.NoError(t, json.Unmarshal(raw, &req))
	b, err := req.Check()
	require.NoError(t, err, "the request is what Postgres built, settings matching the binding")
	require.Equal(t, opened.BindingText, req.Binding)
	require.Equal(t, opened.SettingsText, req.Settings)
	require.Equal(t, []string{bot.Role, helper.Role}, b.Agents)
	require.Len(t, req.CredentialIDs, 1)
	require.Equal(t, passkey.Bytes(person.ID), req.CredentialIDs[0])

	// A signature over another text is refused by Postgres: nothing approved.
	forged, err := person.Sign(approval.Challenge(opened.BindingText+" "), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	status, out = p.approve(opened.ID, secret, approval.NewPluginApprovalResponse(opened.ID, forged))
	require.Equal(t, http.StatusConflict, status, out)
	require.Equal(t, "APPROVAL_INVALID", out["code"])
	require.Equal(t, "The plugin approval code did not verify, so nothing was approved. Approve again on this page.", out["personMessage"])
	require.Zero(t, pluginApprovedRows(t, d, bot.Role))

	signed, err := person.Sign(approval.Challenge(opened.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	status, out = p.approve(opened.ID, secret, approval.NewPluginApprovalResponse(opened.ID, signed))
	require.Equal(t, http.StatusOK, status, out)
	require.Equal(t, "APPROVED", out["status"])
	require.Equal(t, opened.ID.String(), out["approvalId"])
	require.NotContains(t, out, "receipt")
	for _, role := range []string{bot.Role, helper.Role} {
		require.Equal(t, 1, pluginApprovedRows(t, d, role), role)
	}

	// Signed: the page can do nothing more with it.
	status, out = p.approve(opened.ID, secret, approval.NewPluginApprovalResponse(opened.ID, signed))
	require.Equal(t, http.StatusConflict, status, out)
	require.Equal(t, "APPROVAL_INVALID", out["code"])
	require.Equal(t, "This plugin approval is already signed. The plugin starts when the engine restarts.", out["personMessage"])
	status, out = p.issue(opened.ID, opened.BindingText)
	require.Equal(t, http.StatusConflict, status, out)

	// A newer approval of the same entry cancels the pending one.
	first, err := guard.OpenPluginApproval(ctx, bot.Conn, pluginApprovalDetail("0.3.2", bot.Role), guard.PluginSettings{})
	require.NoError(t, err)
	status, out = p.issue(first.ID, first.BindingText)
	require.Equal(t, http.StatusOK, status, out)
	firstSecret := p.secretOf(first.ID, out)
	second, err := guard.OpenPluginApproval(ctx, bot.Conn, pluginApprovalDetail("0.3.3", bot.Role), guard.PluginSettings{})
	require.NoError(t, err)
	status, out = p.get(first.ID, firstSecret)
	require.Equal(t, http.StatusConflict, status, out)
	require.Equal(t, "APPROVAL_INVALID", out["code"])
	require.Contains(t, out["personMessage"], "A newer approval for this plugin replaced this one")

	// Past its expiry: 410, and nothing can be approved.
	status, out = p.issue(second.ID, second.BindingText)
	require.Equal(t, http.StatusOK, status, out)
	secondSecret := p.secretOf(second.ID, out)
	p.offset.Store(int64(25 * time.Hour))
	status, out = p.get(second.ID, secondSecret)
	require.Equal(t, http.StatusGone, status, out)
	require.Equal(t, "APPROVAL_EXPIRED", out["code"])
	require.Contains(t, out["personMessage"], "Nothing was approved; ask the agent for a new link.")
	steps, _ := out["nextSteps"].([]any)
	require.Len(t, steps, 1, "the person's step: ask the agent for a new link")

	// An approval opened in the other database is that agent's alone.
	p.offset.Store(0)
	theirs, err := guard.OpenPluginApproval(ctx, other.Conn, pluginApprovalDetail("0.3.1", other.Role), guard.PluginSettings{})
	require.NoError(t, err)
	status, out = p.issue(theirs.ID, theirs.BindingText)
	require.Equal(t, http.StatusOK, status, out)
	require.Equal(t, other.Role, theirsRequestedBy(t, theirs.BindingText))
}

// TestPluginRoutesOnOlderGuard: an agent whose guard predates plugin
// approvals cannot hold one; the routes answer it as an unknown id, never
// a failed read of a view that does not exist.
func TestPluginRoutesOnOlderGuard(t *testing.T) {
	restore := guardtest.UpToVersion(t, guard.PluginApprovalsVersion-1)
	d := guardtest.New(t).WithDemo(t)
	old := d.NewAgent(t, "old", []string{"public.leads"}, nil)
	restore()
	pg := newPGAgent(t, old.URL, 2)
	origin := "http://localhost:8787"
	srv := pages.New(origin, quietLog())
	pool, err := postgres.NewPool(context.Background(), old.URL, 1)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	srv.Add(pg.service(func(dp *agent.Deps) {
		dp.PagesOrigin, dp.Links, dp.PluginApprovals = origin, links.NewSecrets(time.Now, rand.Reader), pg.store
		dp.Probe = postgres.Probe{Q: pool, Migrations: guard.Migrations()}
	}))
	body := `{"proof":"` + links.IssueProof("{}") + `"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/plugins/"+uuid.Must(uuid.NewV7()).String()+"/links", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

func pluginApprovedRows(t *testing.T, d *guardtest.DB, role string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM basalt_meta.ledger WHERE kind = 'PLUGIN_APPROVED' AND agent = $1`, role).Scan(&n))
	return n
}

func theirsRequestedBy(t *testing.T, binding string) string {
	t.Helper()
	b, err := approval.ParsePluginBinding(binding)
	require.NoError(t, err)
	return b.RequestedBy
}
