package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/platform/keyfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// portalPerson is the person's OS user id in these tests: any id but the
// test's own.
var portalPerson = func() uint32 {
	self := uint32(os.Getuid())
	if self == 2001 {
		return 2002
	}
	return 2001
}()

// portalFixture is a service engine's kept plugins over one agent's guard.
type portalFixture struct {
	t     *testing.T
	base  string
	cfg   config.Config
	s     *plugin.KeptPlugins
	store *plugin.Store
	roles map[string]*guardtest.Agent
	pk    *passkeytest.Authenticator
}

func newPortalFixture(t *testing.T, name string, set func(*config.Config)) *portalFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	base, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	f := &portalFixture{t: t, base: base, roles: map[string]*guardtest.Agent{}}
	state, configPath := filepath.Join(base, "state"), filepath.Join(base, "config", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(configPath), 0o700))
	d := guardtest.New(t).WithDemo(t)
	me, err := user.Current()
	require.NoError(t, err)
	f.cfg = config.Config{Mode: config.ModeService, StateDir: state, SocketDir: filepath.Join(base, "run")}
	a := d.NewAgent(t, name, []string{"public.leads"}, nil)
	f.roles[name] = a
	pool, err := pgxpool.New(context.Background(), a.URL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cc := pool.Config().ConnConfig
	agents := map[string]plugin.KeptAgent{name: plugin.NewKeptAgent(pool, cc.Host, cc.Port, cc.Database, cc.User)}
	f.cfg.Agents = append(f.cfg.Agents, config.Agent{Name: name, OSUser: me.Username})
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, raw, 0o600))
	if set != nil {
		set(&f.cfg)
	}
	f.store, err = plugin.NewPluginhost(state, time.Now)
	require.NoError(t, err)
	f.s = plugin.NewKeptPlugins(f.store, f.cfg, configPath, agents, slog.New(slog.DiscardHandler), pluginPorts)
	f.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, f.pk.Credential(), "app"))
	return f
}

func (f *portalFixture) entries() []config.Plugin {
	f.t.Helper()
	es, err := f.store.Entries(f.cfg)
	require.NoError(f.t, err)
	return es
}

// upload sends files to the kept plugins in parts, as basalt mcp does over
// the person's own socket, and returns the upload's id.
func (f *portalFixture) upload(ctx context.Context, files []plugin.UploadFile) (uuid.UUID, error) {
	begun, err := f.s.UploadBegin(ctx, portalPerson)
	if err != nil {
		return uuid.Nil, err
	}
	part := begun.MaxPartBytes
	for _, file := range files {
		if len(file.Data) == 0 {
			if _, err := f.s.UploadPart(ctx, portalPerson, plugin.PluginUploadPartParams{UploadID: begun.UploadID, Path: file.Path}); err != nil {
				return uuid.Nil, err
			}
			continue
		}
		for off := 0; off < len(file.Data); off += part {
			chunk := file.Data[off:min(off+part, len(file.Data))]
			if _, err := f.s.UploadPart(ctx, portalPerson, plugin.PluginUploadPartParams{
				UploadID: begun.UploadID, Path: file.Path, Offset: int64(off), Data: base64.RawURLEncoding.EncodeToString(chunk),
			}); err != nil {
				return uuid.Nil, err
			}
		}
	}
	return begun.UploadID, nil
}

// portalSource is a plugin's source files and its executables.
func portalSource(version string) ([]plugin.UploadFile, []string) {
	exe := []byte("#!/bin/sh\nexit 0\n" + version)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": %q, "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": "sha256:%x", "share/model.txt": "sha256:%x" },
  "network": { "egress": [] }
}
`, version, sha256.Sum256(exe), sha256.Sum256([]byte("model")))
	return []plugin.UploadFile{
		{Path: plugin.ManifestFile, Data: []byte(manifest)},
		{Path: "bin/acme-ner", Data: exe},
		{Path: "share/model.txt", Data: []byte("model")},
	}, []string{"bin/acme-ner"}
}

// serveAgentSocket serves caller's upload methods of p on a Unix socket under
// dir, as the engine serves them on the agent's own socket, and returns its
// path.
func serveAgentSocket(t *testing.T, dir string, p *pluginRequests, caller string, served func() error) string {
	t.Helper()
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt", Version: "test"}).WithMethods(p.uploadMethods(caller, served))
	sock := filepath.Join(dir, caller+".sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(context.Background(), bufio.NewReader(conn), conn)
			}()
		}
	}()
	return sock
}

// Plugin approval through the portal (CONTRACT.md): on an agent-operated
// engine on the bot's computer, request_plugin hands over a portal short
// link registered at the (fake) Vault; the portal page reads the plugin's
// binding in a session through the Vault, the person's passkey signs it,
// Postgres verifies the signature, and only then does the wait read the
// approval as signed. Without a Vault link nothing is written.
func TestPluginApprovalThroughThePortal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The bot's computer: the engine runs as the agent's own OS user.
	f := newPortalFixture(t, "bot", func(c *config.Config) { c.Mode, c.OperatedBy = "", mcpcontract.OperatedByAgent })
	p := newPluginRequests(map[string]uint32{"bot": portalPerson}, plugin.Callers(f.cfg, portalPerson))
	p.SetKept(f.s)

	stateDir := t.TempDir()
	keys, err := keyfile.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	secrets := links.NewSecrets(time.Now, rand.Reader)
	relay := &lateRelay{}
	pg := newPGAgent(t, f.roles["bot"].URL, 4)
	svc := pg.service(func(d *agent.Deps) {
		d.Core.PagesBase, d.Delivery.Links, d.Delivery.Relay, d.Delivery.Receipts, d.Delivery.Poll = links.Portal, secrets, relay, keys, relayPoll
		d.Core.Commands = d.Core.Commands.OperatedBy(mcpcontract.OperatedByAgent)
		d.Status.OperatedBy, d.Status.SameUser = mcpcontract.OperatedByAgent, true
		d.Plugin.Requests, d.Plugin.Approvals = p, pg.store
	})
	server := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(agent.Tools(svc), agent.WithMeta)...)
	files, executables := portalSource("1.0.0")
	install := func() (map[string]any, bool) {
		t.Helper()
		id, err := f.upload(ctx, files)
		require.NoError(t, err)
		meta := map[string]any{mcpserver.MetaPluginUpload: map[string]any{"uploadId": id.String(), "name": "acme-ner", "executables": executables}}
		return callWithMeta(ctx, t, server, "request_plugin", map[string]any{"source": "/home/bot/acme-ner"}, meta)
	}

	// No Vault socket yet: refused before anything is written.
	body, isError := install()
	require.True(t, isError, "%v", body)
	require.Equal(t, "PLUGIN_REFUSED", body["code"], "%v", body)
	require.Equal(t, plugin.ReasonPluginNoPortalLink, body["reason"])
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
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te)
	require.Equal(t, "PLUGIN_REFUSED", te.Code)
	require.Equal(t, plugin.ReasonPluginNoPortalLink, te.Reason)
	require.Contains(t, te.PersonMessage, "the Vault is off")
	require.Equal(t, []string{toolresult.ActionAskPerson, toolresult.ActionCallTool}, []string{te.NextSteps[0].Action, te.NextSteps[1].Action})

	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	live := linksvc.NewRegistry(quietLog())
	site := newPages(links.Portal, quietLog())
	site.Add(svc)
	ev := openVault(config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}, stateDir, time.Now, quietLog(), live, sessionDispatcher{site})
	require.NotNil(t, ev.Client)
	live.Add("bot", secrets, ev.Client.Unregister)
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ev.Client.Run(runCtx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, ev.Client.Connected, 5*time.Second, 5*time.Millisecond)
	relay.c.Store(ev.Client)

	// Once the Vault answers, basalt mcp's upload goes through.
	up, err := uploader(ctx, dir)
	require.NoError(t, err)
	p.DropUpload("bot", uuid.MustParse(up.UploadID))

	body, isError = install()
	require.False(t, isError, "%v", body)
	require.Equal(t, plugin.PluginStatePending, body["state"])
	idText, secret := portalLink(t, body["approvalUrl"].(string), "plugins")
	require.Equal(t, body["approvalId"], idText)
	id := uuid.MustParse(idText)
	require.Len(t, f.entries(), 1, "the entry is written and waits for the approval")
	st, err := p.PluginApproval(ctx, "bot", id)
	require.NoError(t, err)
	require.Equal(t, plugin.PluginStatePending, st.State, "nothing is served before the signature")

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
	require.Equal(t, plugin.PluginStatePending, st.State)

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
	require.Equal(t, plugin.PluginStateApproved, body["state"], "signed in Postgres; the harness runs no plugin")
}

// pluginSigned is the approve body: signer's assertion over the binding the
// page was shown.
func pluginSigned(t *testing.T, signer *passkeytest.Authenticator, req approval.PluginRequest) string {
	t.Helper()
	as, err := signer.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	body, err := json.Marshal(approvaltest.NewResponse(req.ApprovalID, as))
	require.NoError(t, err)
	return string(body)
}

// callWithMeta runs one tools/call with the request's _meta, as basalt mcp
// forwards a call with its upload.
func callWithMeta(ctx context.Context, t *testing.T, server *mcpserver.Server, tool string, args, meta map[string]any) (map[string]any, bool) {
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
