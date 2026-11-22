package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// relayPoll is how often a waiting write or request_revert reads whether
// the person signed, in these tests.
const relayPoll = 50 * time.Millisecond

// relayEnv is an agent on real Postgres whose engine hands portal short
// links registered with a fake Vault, as an engine with vault ON does: its
// tools answer through an MCP server, and the portal's own page code reaches
// it through the Vault (testdata/page_driver.mjs).
type relayEnv struct {
	d      *guardtest.DB
	person *passkeytest.Authenticator
	server *mcp.Server
	v      *vaulttest.Vault
	keys   *channel.EngineKeys
}

func newRelayEnv(t *testing.T) *relayEnv {
	t.Helper()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	leads := []string{"public.leads"}
	bot := d.NewAgent(t, "bot", leads, leads)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))

	// The engine's keys sign the receipts and open the Vault socket.
	stateDir := t.TempDir()
	keys, err := channel.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	secrets := links.NewSecrets(time.Now, rand.Reader)
	relay := &lateRelay{}
	svc := newPGAgent(t, bot.URL, 4).service(func(dp *agent.Deps) {
		dp.PagesBase, dp.Links, dp.Relay, dp.Receipts, dp.Poll = links.Portal, secrets, relay, keys, relayPoll
	})

	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	live := newRelayLinks(quietLog())
	site := pages.New(links.Portal, quietLog())
	site.Add(svc)
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, stateDir, time.Now, quietLog(), live, site)
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
	return &relayEnv{d: d, person: person, server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...), v: v, keys: keys}
}

// call runs one tools/call as the agent would and returns its body and
// isError.
func (e *relayEnv) call(t *testing.T, tool string, args any) (map[string]any, bool) {
	t.Helper()
	body, isError, err := e.callErr(tool, args)
	require.NoError(t, err)
	return body, isError
}

// callErr is call without the test, for a call made in the background.
func (e *relayEnv) callErr(tool string, args any) (map[string]any, bool, error) {
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	if err != nil {
		return nil, false, err
	}
	var out bytes.Buffer
	if err := e.server.Serve(context.Background(), bytes.NewReader(append(req, '\n')), &out); err != nil {
		return nil, false, err
	}
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return nil, false, fmt.Errorf("%w: %s", err, out.String())
	}
	if len(resp.Result.Content) != 1 {
		return nil, false, fmt.Errorf("one content item: %s", out.String())
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(resp.Result.Content[0].Text), &body); err != nil {
		return nil, false, fmt.Errorf("%w: %s", err, resp.Result.Content[0].Text)
	}
	return body, resp.Result.IsError, nil
}

// later runs call in the background, as an agent's waiting call.
func (e *relayEnv) later(t *testing.T, tool string, args any) <-chan map[string]any {
	t.Helper()
	out := make(chan map[string]any, 1)
	go func() {
		body, _, err := e.callErr(tool, args)
		if err != nil {
			body = map[string]any{"callError": err.Error()}
		}
		out <- body
	}()
	return out
}

func (e *relayEnv) leadStatus(t *testing.T, id int) string {
	t.Helper()
	var s string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT status FROM public.leads WHERE id = $1`, id).Scan(&s))
	return s
}

// portalLink checks a link is a portal short link for page and returns its
// item id and secret.
func portalLink(t *testing.T, link, page string) (string, string) {
	t.Helper()
	prefix := links.Portal + "/" + page + "/"
	require.True(t, strings.HasPrefix(link, prefix), "a portal short link: %s", link)
	id, _, ok := strings.Cut(strings.TrimPrefix(link, prefix), "#")
	require.True(t, ok)
	secret := links.SecretOf(link)
	require.Len(t, secret, 22)
	return id, secret
}

// pageDriver is testdata/page_driver.mjs: the portal's page code under
// node, one command at a time.
type pageDriver struct {
	in  io.WriteCloser
	out *bufio.Scanner
}

func startPageDriver(t *testing.T, vaultURL string) *pageDriver {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; make web-check needs it too")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	cmd := exec.CommandContext(ctx, node, "testdata/page_driver.mjs", vaultURL)
	in, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
		cancel()
		if stderr.Len() > 0 {
			t.Logf("page driver stderr: %s", stderr.String())
		}
	})
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	return &pageDriver{in: in, out: sc}
}

// do sends one command and returns its answer; an answer with error fails
// the test unless wantError.
func (p *pageDriver) do(t *testing.T, cmd map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(cmd)
	require.NoError(t, err)
	_, err = p.in.Write(append(b, '\n'))
	require.NoError(t, err)
	require.True(t, p.out.Scan(), "the page driver answered %v", cmd["op"])
	var out map[string]any
	require.NoError(t, json.Unmarshal(p.out.Bytes(), &out), p.out.Text())
	return out
}

func (p *pageDriver) ok(t *testing.T, cmd map[string]any) map[string]any {
	t.Helper()
	out := p.do(t, cmd)
	require.NotContains(t, out, "error", "%v: %v", cmd["op"], out["error"])
	return out
}

var rawURL = base64.RawURLEncoding

// sign is the person's passkey prompt: the assertion over the challenge
// the page code asked for, as the browser hands it to the page.
func sign(t *testing.T, person *passkeytest.Authenticator, read map[string]any) map[string]string {
	t.Helper()
	ch, err := rawURL.DecodeString(read["challenge"].(string))
	require.NoError(t, err)
	ids, ok := read["credentialIds"].([]any)
	require.True(t, ok)
	require.Contains(t, ids, rawURL.EncodeToString(person.ID), "the page offers the person's passkey")
	as, err := person.Sign(ch, passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return map[string]string{
		"credentialId": rawURL.EncodeToString(as.CredentialID), "authenticatorData": rawURL.EncodeToString(as.AuthenticatorData),
		"clientDataJson": rawURL.EncodeToString(as.ClientDataJSON), "signature": rawURL.EncodeToString(as.Signature),
	}
}

// requireReceiptLine checks the page shows the engine's receipt with the
// session's fingerprint, never as verified.
func (e *relayEnv) requireReceiptLine(t *testing.T, signed map[string]any) {
	t.Helper()
	result, ok := signed["result"].(map[string]any)
	require.True(t, ok, "%v", signed)
	token, ok := result["receipt"].(string)
	require.True(t, ok, "the answer carries the engine's receipt: %v", result)
	_, err := channel.VerifyReceipt(token, e.keys.PublicKeySPKI())
	require.NoError(t, err, "signed by this engine's key")
	line := signed["receiptLine"].(string)
	require.Contains(t, line, "Receipt from the engine with fingerprint "+e.keys.Fingerprint())
	require.Contains(t, line, "Compare this fingerprint with the one the agent showed you in the chat")
	require.NotContains(t, strings.ToLower(line), "verified")
}

// A held write approved on the portal page: the agent's waiting write
// returns APPLIED once the page code, through the Vault, posts the
// person's passkey signature. Nothing is pasted anywhere.
func TestRelayApprovalEndToEnd(t *testing.T) {
	t.Parallel()
	e := newRelayEnv(t)
	run, isError := e.call(t, "run_start", map[string]any{"intent": "Close the stale leads"})
	require.False(t, isError, "%v", run)
	args := map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", 21, 35},
		"intent": "Leads 21 to 35 went cold", "runId": run["runId"],
	}
	held, isError := e.call(t, "write", args)
	require.True(t, isError)
	require.Equal(t, "APPROVAL_REQUIRED", held["code"], "%v", held)
	ap := held["approval"].(map[string]any)
	id, secret := portalLink(t, ap["approvalUrl"].(string), "approvals")
	require.Equal(t, ap["approvalId"], id)

	args["approvalId"] = id
	waiting := e.later(t, "write", args)

	p := startPageDriver(t, e.v.URL())
	opened := p.ok(t, map[string]any{"op": "open", "secret": secret})
	require.Equal(t, e.keys.Fingerprint(), opened["engine"].(map[string]any)["fingerprint"])
	read := p.ok(t, map[string]any{"op": "read", "kind": "approvals", "id": id, "secret": secret})
	require.Equal(t, id, read["id"])
	signed := p.ok(t, map[string]any{"op": "sign", "kind": "approvals", "id": id, "secret": secret, "assertion": sign(t, e.person, read)})
	require.Equal(t, "APPROVED", signed["result"].(map[string]any)["status"])
	e.requireReceiptLine(t, signed)

	select {
	case body := <-waiting:
		require.Equal(t, agent.StatusApplied, body["status"], "%v", body)
	case <-time.After(30 * time.Second):
		t.Fatal("the waiting write did not return")
	}
	require.Equal(t, "closed", e.leadStatus(t, 21))
}

// winRun applies a small write in a run and returns the run's id.
func (e *relayEnv) winRun(t *testing.T, ids string) string {
	t.Helper()
	run, isError := e.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	out, isError := e.call(t, "write", map[string]any{"sql": "UPDATE leads SET status = 'won' WHERE id IN (" + ids + ")", "intent": "They signed", "runId": run["runId"]})
	require.False(t, isError, "%v", out)
	return run["runId"].(string)
}

// prepareRevert asks for the revert of a run and returns its id and secret.
func (e *relayEnv) prepareRevert(t *testing.T, runID string) (string, string) {
	t.Helper()
	body, isError := e.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo the win"})
	require.False(t, isError, "%v", body)
	id, secret := portalLink(t, body["revertUrl"].(string), "reverts")
	require.Equal(t, body["revertId"], id)
	return id, secret
}

// A revert signed on the portal page: the agent's waiting request_revert
// returns APPLIED after the page code posts apply through the Vault.
func TestRelayRevertEndToEnd(t *testing.T) {
	t.Parallel()
	e := newRelayEnv(t)
	id, secret := e.prepareRevert(t, e.winRun(t, "81, 82"))
	require.Equal(t, "won", e.leadStatus(t, 81))
	waiting := e.later(t, "request_revert", map[string]any{"revertId": id})

	p := startPageDriver(t, e.v.URL())
	p.ok(t, map[string]any{"op": "open", "secret": secret})
	read := p.ok(t, map[string]any{"op": "read", "kind": "reverts", "id": id, "secret": secret})
	require.Equal(t, id, read["id"])
	signed := p.ok(t, map[string]any{"op": "sign", "kind": "reverts", "id": id, "secret": secret, "assertion": sign(t, e.person, read)})
	e.requireReceiptLine(t, signed)

	select {
	case body := <-waiting:
		require.Contains(t, []any{"APPLIED", "APPLYING"}, body["status"], "%v", body)
	case <-time.After(30 * time.Second):
		t.Fatal("the waiting request_revert did not return")
	}
	require.Equal(t, "open", e.leadStatus(t, 81))
}

// A widen on the portal page rotates the revert's link: the page's session
// stays open, its later requests carry the new secret, and the old secret
// is answered 404 in it.
func TestRelayRevertWidenKeepsTheSession(t *testing.T) {
	t.Parallel()
	e := newRelayEnv(t)
	runID := e.winRun(t, "41, 42")
	id, secret := e.prepareRevert(t, runID)
	revertID := uuid.MustParse(id)

	p := startPageDriver(t, e.v.URL())
	p.ok(t, map[string]any{"op": "open", "secret": secret})
	readPath := "/api/v1/reverts/" + id
	first := p.ok(t, map[string]any{"op": "request", "method": http.MethodGet, "path": readPath, "secret": secret})
	require.EqualValues(t, http.StatusOK, first["status"], first["body"])
	var proposal revert.Request
	require.NoError(t, json.Unmarshal([]byte(first["body"].(string)), &proposal))

	// The person's proven widen to the same run, with the page's new secret.
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	newSecret := rawURL.EncodeToString(raw)
	key, err := revert.RescopeKey(raw)
	require.NoError(t, err)
	sel := revert.Select{Scope: revert.ScopeRun, ScopeID: uuid.MustParse(runID)}
	selJSON, err := json.Marshal(sel)
	require.NoError(t, err)
	var norm string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	as, err := e.person.Sign(revert.RescopeChallenge(revertID, proposal.RescopeNonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	widen, err := json.Marshal(agent.ScopeRequest{Select: sel, NewSecret: newSecret, Proof: &agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
	require.NoError(t, err)
	r := p.ok(t, map[string]any{"op": "request", "method": http.MethodPost, "path": readPath + "/scope", "secret": secret, "body": string(widen)})
	require.EqualValues(t, http.StatusOK, r["status"], r["body"])
	require.Empty(t, r["ended"], "the session stays open")

	r = p.ok(t, map[string]any{"op": "request", "method": http.MethodGet, "path": readPath, "secret": newSecret})
	require.EqualValues(t, http.StatusOK, r["status"], r["body"])
	r = p.ok(t, map[string]any{"op": "request", "method": http.MethodGet, "path": readPath, "secret": secret})
	require.EqualValues(t, http.StatusNotFound, r["status"], "the old secret reads as an unknown id")
	require.Empty(t, r["ended"])
}

// A reject on the portal page revokes the revert's link: the answer reaches
// the page, then its session ends with LINK_REFUSED and the page reads the
// link as gone.
func TestRelayRevertRejectEndsTheSession(t *testing.T) {
	t.Parallel()
	e := newRelayEnv(t)
	id, secret := e.prepareRevert(t, e.winRun(t, "51"))

	p := startPageDriver(t, e.v.URL())
	p.ok(t, map[string]any{"op": "open", "secret": secret})
	note := "Not this one"
	body, err := json.Marshal(agent.RejectRequest{Note: &note})
	require.NoError(t, err)
	r := p.ok(t, map[string]any{"op": "request", "method": http.MethodPost, "path": "/api/v1/reverts/" + id + "/reject", "secret": secret, "body": string(body)})
	require.EqualValues(t, http.StatusOK, r["status"], r["body"])

	require.Eventually(t, func() bool {
		return p.ok(t, map[string]any{"op": "state"})["ended"] == "LINK_REFUSED"
	}, 5*time.Second, 20*time.Millisecond, "the engine ends the session with LINK_REFUSED")
	gone := p.do(t, map[string]any{"op": "read", "kind": "reverts", "id": id, "secret": secret})
	failure, ok := gone["error"].(map[string]any)
	require.True(t, ok, "%v", gone)
	require.Equal(t, "NOT_FOUND", failure["code"])
	require.Equal(t, "LINK", failure["reason"])
	require.Equal(t, "won", e.leadStatus(t, 51), "nothing reverted")
}
