package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/keyfile"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/pages"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// Plugin approval through the portal (CONTRACT.md): on an agent-operated
// engine on the bot's computer, request_plugin hands over a portal short
// link registered at the (fake) Vault; the portal page reads the plugin's
// binding in a session through the Vault, the person's passkey signs it,
// Postgres verifies the signature, and only then does the wait read the
// approval as signed. Without a Vault link nothing is written.
func TestPluginApprovalThroughThePortal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newKeptFixture(t, []string{"bot"})
	// The bot's computer: the engine runs as the agent's own OS user.
	f.cfg.Mode, f.cfg.OperatedBy = "", mcpcontract.OperatedByAgent
	f.s.cfg = f.cfg
	p := &pluginRequests{uids: map[string]uint32{"bot": keptPerson}, admitted: pluginCallers(f.cfg, keptPerson)}
	p.kept.Store(f.s)

	stateDir := t.TempDir()
	keys, err := keyfile.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	secrets := links.NewSecrets(time.Now, rand.Reader)
	relay := &lateRelay{}
	pg := newPGAgent(t, f.roles["bot"].URL, 4)
	svc := pg.service(func(d *agent.Deps) {
		d.PagesBase, d.Links, d.Relay, d.Receipts, d.Poll = links.Portal, secrets, relay, keys, relayPoll
		d.Commands = d.Commands.OperatedBy(mcpcontract.OperatedByAgent)
		d.OperatedBy, d.SameUser = mcpcontract.OperatedByAgent, true
		d.PluginRequests, d.PluginApprovals = p, pg.store
	})
	server := mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...)
	files, executables := source("1.0.0")
	install := func() (map[string]any, bool) {
		t.Helper()
		id, err := f.client.PluginUpload(ctx, files)
		require.NoError(t, err)
		meta := map[string]any{mcp.MetaPluginUpload: map[string]any{"uploadId": id.String(), "name": "acme-ner", "executables": executables}}
		return callWithMeta(ctx, t, server, "request_plugin", map[string]any{"source": "/home/bot/acme-ner"}, meta)
	}

	// No Vault socket yet: refused before anything is written.
	body, isError := install()
	require.True(t, isError, "%v", body)
	require.Equal(t, "PLUGIN_REFUSED", body["code"], "%v", body)
	require.Equal(t, agent.ReasonPluginNoPortalLink, body["reason"])
	require.Empty(t, f.entries(), "nothing written without a portal link")

	// basalt mcp uploads on an agent-operated engine; the engine refuses the
	// upload where the tool would, and the agent gets the tool's own
	// refusal, its steps included.
	dir := t.TempDir()
	for _, file := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, file.Path)), 0o755))
		mode := os.FileMode(0o644)
		if slices.Contains(executables, file.Path) {
			mode = 0o755
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, file.Path), file.Data, mode))
	}
	uploader := shim.NewPluginUploader(serveAgentSocket(t, f.base, p, "bot", svc.PluginUploadsServed))
	_, err = uploader(ctx, dir)
	var te *mcp.ToolError
	require.ErrorAs(t, err, &te)
	require.Equal(t, "PLUGIN_REFUSED", te.Code)
	require.Equal(t, agent.ReasonPluginNoPortalLink, te.Reason)
	require.Contains(t, te.PersonMessage, "the Vault is off")
	require.Equal(t, []string{mcp.ActionAskPerson, mcp.ActionCallTool}, []string{te.NextSteps[0].Action, te.NextSteps[1].Action})

	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	live := newRelayLinks(quietLog())
	site := pages.New(links.Portal, quietLog())
	site.Add(svc)
	ev := openVault(config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}, stateDir, time.Now, quietLog(), live, site)
	require.NotNil(t, ev.client)
	live.add("bot", secrets, ev.client.Unregister)
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ev.client.Run(runCtx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, ev.client.Connected, 5*time.Second, 5*time.Millisecond)
	relay.c.Store(ev.client)

	// Once the Vault answers, basalt mcp's upload goes through.
	up, err := uploader(ctx, dir)
	require.NoError(t, err)
	p.DropUpload("bot", uuid.MustParse(up.UploadID))

	body, isError = install()
	require.False(t, isError, "%v", body)
	require.Equal(t, agent.PluginStatePending, body["state"])
	idText, secret := portalLink(t, body["approvalUrl"].(string), "plugins")
	require.Equal(t, body["approvalId"], idText)
	id := uuid.MustParse(idText)
	require.Len(t, f.entries(), 1, "the entry is written and waits for the approval")
	st, err := p.PluginApproval(ctx, "bot", id)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStatePending, st.State, "nothing is served before the signature")

	linkKeys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	wctx := waitCtx(t)
	page, err := pagetest.Open(wctx, v.URL(), linkKeys)
	require.NoError(t, err)
	t.Cleanup(page.Close)
	do := func(method, path, body string) pagetest.Reply {
		t.Helper()
		headers := pagetest.Headers(secret)
		if method == http.MethodPost {
			headers = pagetest.PostHeaders(secret)
		}
		r, err := page.Do(wctx, method, path, headers, body, 0)
		require.NoError(t, err)
		return r
	}

	// The page reads the plugin's details from the engine over the channel.
	read := do(http.MethodGet, "/api/v1/plugins/"+idText, "")
	require.Equal(t, http.StatusOK, read.Status, read.Body)
	var req approval.PluginRequest
	require.NoError(t, json.Unmarshal([]byte(read.Body), &req))
	b, err := req.Check()
	require.NoError(t, err)
	require.Equal(t, "acme-ner", b.Name)
	require.Equal(t, "1.0.0", b.Version)
	require.Equal(t, []string{f.roles["bot"].Role}, b.Agents)
	require.NotEmpty(t, req.CredentialIDs)

	// The session is for this plugin approval only.
	other := do(http.MethodGet, "/api/v1/approvals/"+idText, "")
	require.Equal(t, http.StatusNotFound, other.Status, other.Body)

	// Another key's signature: Postgres refuses it, and nothing is approved.
	stranger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	refused := do(http.MethodPost, "/api/v1/plugins/"+idText+"/approve", pluginSigned(t, stranger, req))
	require.Equal(t, http.StatusConflict, refused.Status, refused.Body)
	st, err = p.PluginApproval(ctx, "bot", id)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStatePending, st.State)

	// The person's passkey: Postgres verifies it, and the answer carries no
	// receipt (there is no receipt kind for a plugin approval). The portal's
	// own page code reads and posts it through the Vault; only a local run
	// without node signs in Go instead.
	var answer map[string]any
	_, noNode := osexec.LookPath("node")
	if noNode != nil && os.Getenv("CI") != "" {
		t.Fatalf("CI runs the portal's page code: node is not installed (%v)", noNode)
	}
	if noNode == nil {
		drv := startPageDriver(t, v.URL())
		drv.ok(t, map[string]any{"op": "open", "secret": secret})
		read := drv.ok(t, map[string]any{"op": "read", "kind": "plugins", "id": idText, "secret": secret})
		require.Equal(t, idText, read["id"])
		signed := drv.ok(t, map[string]any{"op": "sign", "kind": "plugins", "id": idText, "secret": secret, "assertion": sign(t, f.pk, read)})
		answer = signed["result"].(map[string]any)
	} else {
		ok := do(http.MethodPost, "/api/v1/plugins/"+idText+"/approve", pluginSigned(t, f.pk, req))
		require.Equal(t, http.StatusOK, ok.Status, ok.Body)
		require.NoError(t, json.Unmarshal([]byte(ok.Body), &answer))
	}
	require.Equal(t, "APPROVED", answer["status"])
	require.Equal(t, idText, answer["approvalId"])
	require.NotContains(t, answer, "receipt")
	require.NotContains(t, answer, "noReceipt")

	body, isError = callWithMeta(ctx, t, server, "request_plugin", map[string]any{"approvalId": idText, "waitForApproval": 0}, nil)
	require.False(t, isError, "%v", body)
	require.Equal(t, agent.PluginStateApproved, body["state"], "signed in Postgres; the harness runs no plugin")
}

// pluginSigned is the approve body: signer's assertion over the binding the
// page was shown.
func pluginSigned(t *testing.T, signer *passkeytest.Authenticator, req approval.PluginRequest) string {
	t.Helper()
	as, err := signer.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	body, err := json.Marshal(approval.NewResponse(req.ApprovalID, as))
	require.NoError(t, err)
	return string(body)
}

// callWithMeta runs one tools/call with the request's _meta, as basalt mcp
// forwards a call with its upload.
func callWithMeta(ctx context.Context, t *testing.T, server *mcp.Server, tool string, args, meta map[string]any) (map[string]any, bool) {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args}
	if meta != nil {
		params["_meta"] = meta
	}
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, server.Serve(ctx, bytes.NewReader(append(req, '\n')), &out))
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp), out.String())
	require.Len(t, resp.Result.Content, 1, fmt.Sprint(out.String()))
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &body))
	return body, resp.Result.IsError
}
