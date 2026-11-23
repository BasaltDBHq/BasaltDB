package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// heldAgent holds one write for approval. Its relay checks the person's
// passkey signature over the binding as basalt_meta.submit_approval does
// (approval.Verify), so the session must carry a real signature through.
type heldAgent struct {
	secrets *links.Secrets
	id      uuid.UUID
	binding string
	lines   []string
	cred    passkey.Credential
	// receipt is what RelayApproval returns.
	receipt agent.Receipt

	mu       sync.Mutex
	approved bool
}

func (a *heldAgent) ApprovalRequest(_ context.Context, id uuid.UUID) (approval.Request, error) {
	if id != a.id {
		return approval.Request{}, agent.ErrNotThisAgent
	}
	return approval.Request{ApprovalID: id, Binding: a.binding, Lines: a.lines}, nil
}

func (a *heldAgent) RelayApproval(_ context.Context, r approval.Response) (agent.Receipt, error) {
	if r.ApprovalID != a.id {
		return agent.Receipt{}, agent.ErrNotThisAgent
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.approved {
		return agent.Receipt{}, &toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Message: "this approval was already used"}
	}
	if _, err := approvaltest.Verify(a.binding, a.cred, r); err != nil {
		return agent.Receipt{}, &toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Message: "the signature does not verify"}
	}
	a.approved = true
	return a.receipt, nil
}

func (a *heldAgent) isApproved() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.approved
}

func (a *heldAgent) RevertRequest(context.Context, uuid.UUID, string) (revert.Request, error) {
	return revert.Request{}, agent.ErrNotThisAgent
}

func (a *heldAgent) RescopeRevert(context.Context, uuid.UUID, string, agent.ScopeRequest) (agent.ScopeResponse, error) {
	return agent.ScopeResponse{}, agent.ErrNotThisAgent
}

func (a *heldAgent) CheckResetLink(uuid.UUID, string) bool { return false }

func (a *heldAgent) RejectRevert(context.Context, uuid.UUID, string, agent.RejectRequest) (agent.RejectResponse, error) {
	return agent.RejectResponse{}, agent.ErrNotThisAgent
}

func (a *heldAgent) RevealApproval(context.Context, uuid.UUID, string, agent.RevealRequest) (approval.RevealAnswer, error) {
	return approval.RevealAnswer{}, agent.ErrNotThisAgent
}

func (a *heldAgent) RevealRevert(context.Context, uuid.UUID, string, agent.RevealRequest) (approval.RevealAnswer, error) {
	return approval.RevealAnswer{}, agent.ErrNotThisAgent
}

func (a *heldAgent) RelayRevert(context.Context, revert.Response) (action.AppliedRevert, agent.Receipt, error) {
	return action.AppliedRevert{}, agent.Receipt{}, agent.ErrNotThisAgent
}

func (a *heldAgent) CheckLink(id uuid.UUID, secret string) bool { return a.secrets.Check(id, secret) }

func (a *heldAgent) PageFailure(err error) *toolresult.ToolError { return AgentErrors().ToolError(err) }

// intentMarker is in the held write's binding: it must never cross the
// Vault's sockets in the clear.
const intentMarker = "raise-the-price-of-every-lead"

func heldBinding(id uuid.UUID, lines []string) string {
	return fmt.Sprintf(`{"kind":"APPROVE","approvalId":%q,"database":"app","agent":"demo_bot","runId":%q,"taskId":null,`+
		`"intent":%q,"statement":"UPDATE leads SET price = price * 2","params":[],"assignedColumns":["price"],`+
		`"rows":1,"rowsHash":%q,"expiresAt":"2026-11-13T09:00:00Z"}`,
		id, uuid.Must(uuid.NewV7()), intentMarker, approval.RowsHash(lines))
}

// wire records every message that crosses the fake Vault: session bytes
// both ways, and everything the engine sends on its socket.
type wire struct {
	mu      sync.Mutex
	session []vaulttest.Message
	engine  [][]byte
}

func (w *wire) tamper(m vaulttest.Message) []vaulttest.Delivery {
	w.mu.Lock()
	m.Data = slices.Clone(m.Data)
	w.session = append(w.session, m)
	w.mu.Unlock()
	return []vaulttest.Delivery{vaulttest.Forward(m)}
}

func (w *wire) observe(_ string, _ websocket.MessageType, data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.engine = append(w.engine, slices.Clone(data))
}

// vaultSession is an engine with one held write, a fake Vault, and the
// relay link the engine issued for the write.
type vaultSession struct {
	v      *vaulttest.Vault
	wire   *wire
	agent  *heldAgent
	store  *links.Secrets
	person *passkeytest.Authenticator
	secret string
	client *vault.Client
	keys   channel.LinkKeys
}

func newVaultSession(t *testing.T) *vaultSession {
	t.Helper()
	w := &wire{}
	return newVaultSessionWith(t, w, vaulttest.Options{Tamper: w.tamper, OnEngineMessage: w.observe})
}

// newVaultSessionWith is newVaultSession behind a fake Vault with opts.
func newVaultSessionWith(t *testing.T, w *wire, opts vaulttest.Options) *vaultSession {
	t.Helper()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	id := uuid.Must(uuid.NewV7())
	lines := []string{`{"op":"UPDATE","table":"public.leads","cascaded":false}`}
	store := links.NewSecrets(time.Now, rand.Reader)
	held := &heldAgent{
		secrets: store, id: id, binding: heldBinding(id, lines), lines: lines, cred: person.Credential(),
		receipt: agent.Receipt{Token: "basalt-receipt.1.cA.cw"},
	}
	s := serveOverVaultWith(t, w, opts, held, store, id)
	s.agent, s.person = held, person
	return s
}

// serveOverVault connects an engine whose pages serve a to a fake Vault
// that records into w, and issues and registers a relay link for item id.
func serveOverVault(t *testing.T, w *wire, a pageserver.Agent, store *links.Secrets, id uuid.UUID) *vaultSession {
	t.Helper()
	return serveOverVaultWith(t, w, vaulttest.Options{Tamper: w.tamper, OnEngineMessage: w.observe}, a, store, id)
}

// serveOverVaultWith is serveOverVault with the fake Vault's options.
func serveOverVaultWith(t *testing.T, w *wire, opts vaulttest.Options, a pageserver.Agent, store *links.Secrets, id uuid.UUID) *vaultSession {
	t.Helper()
	v := vaulttest.New(opts)
	t.Cleanup(v.Close)
	relay := linksvc.NewRegistry(quietLog())
	site := newPages(links.Portal, quietLog())
	site.Add(a)
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, t.TempDir(), time.Now, quietLog(), relay, sessionDispatcher{site})
	require.NotNil(t, ev.client)
	relay.Add("bot", store, ev.client.Unregister)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ev.client.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, ev.client.Connected, 5*time.Second, 5*time.Millisecond)

	secret, token, err := store.IssueRelay(id, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, ev.client.Register(context.Background(), token, time.Now().Add(time.Hour)))
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	return &vaultSession{v: v, client: ev.client, wire: w, store: store, secret: secret, keys: keys}
}

func (s *vaultSession) open(t *testing.T) *pagetest.Page {
	t.Helper()
	p, err := pagetest.Open(waitCtx(t), s.v.URL(), s.keys)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}

func waitCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func (s *vaultSession) approvalPath() string { return "/api/v1/approvals/" + s.agent.id.String() }

// signed is the approve body: the person's (or another key's) assertion
// over the binding the page was shown.
func signed(t *testing.T, signer *passkeytest.Authenticator, req approval.Request) string {
	t.Helper()
	as, err := signer.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	body, err := json.Marshal(approvaltest.NewResponse(req.ApprovalID, as))
	require.NoError(t, err)
	return string(body)
}

// A page holding the portal short link reads the held write and approves
// it through the Vault. Only the person's passkey approves: another key's
// signature is refused, as on loopback.
func TestVaultSessionApprovesAHeldWrite(t *testing.T) {
	t.Parallel()
	s := newVaultSession(t)
	p := s.open(t)
	ctx := waitCtx(t)

	r, err := p.Do(ctx, http.MethodGet, s.approvalPath(), pagetest.Headers(s.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	require.Equal(t, "application/json", r.ContentType)
	var req approval.Request
	require.NoError(t, json.Unmarshal([]byte(r.Body), &req))
	require.Equal(t, s.agent.binding, req.Binding)
	_, err = req.Check()
	require.NoError(t, err, "the page checks the binding against the rows it shows")

	// Another key's signature is relayed and refused: the session carries
	// signatures, it does not make them.
	thief, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	r, err = p.Do(ctx, http.MethodPost, s.approvalPath()+"/approve", pagetest.PostHeaders(s.secret), signed(t, thief, req), 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, r.Status)
	require.Contains(t, r.Body, `"code":"APPROVAL_INVALID"`)
	require.False(t, s.agent.isApproved())

	r, err = p.Do(ctx, http.MethodPost, s.approvalPath()+"/approve", pagetest.PostHeaders(s.secret), signed(t, s.person, req), 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status, r.Body)
	require.JSONEq(t, fmt.Sprintf(`{"approvalId":%q,"status":"APPROVED","receipt":"basalt-receipt.1.cA.cw"}`, s.agent.id), r.Body)
	require.True(t, s.agent.isApproved())

	r, err = p.Do(ctx, http.MethodPost, s.approvalPath()+"/approve", pagetest.PostHeaders(s.secret), signed(t, s.person, req), 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, r.Status, "a used approval is refused")

	s.requireNoPlaintext(t, req, signed(t, s.person, req))
}

// requireNoPlaintext checks every message that crossed the Vault: session
// bytes are message 1, message 2 or padded frames, and nothing the engine
// or the page sent holds a request, a response, the link secret or its psk.
func (s *vaultSession) requireNoPlaintext(t *testing.T, req approval.Request, body string) {
	t.Helper()
	s.wire.mu.Lock()
	defer s.wire.mu.Unlock()
	secrets := []string{
		s.secret, s.agent.id.String(), intentMarker, req.Binding, approval.RowsHash(s.agent.lines),
		links.SecretHeader, "REQUEST", "RESPONSE", "CONTINUE", "APPROVED", "approvalId", "application/json",
		base64.RawURLEncoding.EncodeToString(s.keys.PSK[:]), string(s.keys.PSK[:]), body[:40],
	}
	require.NotEmpty(t, s.wire.session)
	firsts := map[[2]any]bool{}
	frames := 0
	for _, m := range s.wire.session {
		for _, secret := range secrets {
			require.False(t, bytes.Contains(m.Data, []byte(secret)), "%q crossed the Vault in the clear", secret)
		}
		key := [2]any{m.Session.SID, m.Dir}
		if !firsts[key] {
			firsts[key] = true
			want := byte(0x01) // message 1, page to engine
			if m.Dir == vaulttest.ToPage {
				want = 0x02 // message 2
			}
			require.Equal(t, []byte{0x01, want}, m.Data[:2])
			continue
		}
		frames++
		require.Equal(t, []byte{0x01, 0x03}, m.Data[:2], "every message after the handshake is a frame")
		padded := len(m.Data) - 18
		require.True(t, padded >= 1024 && padded <= 32768 && padded&(padded-1) == 0,
			"a frame of %d bytes is not a padding bucket", len(m.Data))
	}
	require.Positive(t, frames)
	for _, m := range s.wire.engine {
		for _, secret := range secrets {
			require.False(t, bytes.Contains(m, []byte(secret)), "%q crossed the engine's socket in the clear", secret)
		}
	}
}

// In a session the pages API holds the loopback rules: the session's own
// item and link secret only, the allowlisted routes only, the portal's
// origin, and the same refusals. Every unknown route, item or secret reads
// as one unknown id.
func TestVaultSessionKeepsThePagesRules(t *testing.T) {
	t.Parallel()
	s := newVaultSession(t)
	p := s.open(t)
	ctx := waitCtx(t)
	do := func(method, path string, headers map[string]string, body string) pagetest.Reply {
		t.Helper()
		r, err := p.Do(ctx, method, path, headers, body, 0)
		require.NoError(t, err)
		return r
	}
	other := make([]byte, channel.SecretLen)
	_, err := rand.Read(other)
	require.NoError(t, err)
	otherSecret := base64.RawURLEncoding.EncodeToString(other)

	unknown := do(http.MethodGet, "/api/v1/approvals/"+uuid.Must(uuid.NewV7()).String(), pagetest.Headers(s.secret), "")
	require.Equal(t, http.StatusNotFound, unknown.Status)
	require.Contains(t, unknown.Body, `"code":"NOT_FOUND"`)
	sameAsUnknown := map[string]pagetest.Reply{
		"another secret":     do(http.MethodGet, s.approvalPath(), pagetest.Headers(otherSecret), ""),
		"no secret":          do(http.MethodGet, s.approvalPath(), map[string]string{"origin": links.Portal}, ""),
		"an upper-case id":   do(http.MethodGet, "/api/v1/approvals/"+strings.ToUpper(s.agent.id.String()), pagetest.Headers(s.secret), ""),
		"the links route":    do(http.MethodPost, s.approvalPath()+"/links", pagetest.PostHeaders(s.secret), `{"proof":"x"}`),
		"healthz":            do(http.MethodGet, "/healthz", pagetest.Headers(s.secret), ""),
		"a page":             do(http.MethodGet, "/approvals/"+s.agent.id.String(), pagetest.Headers(s.secret), ""),
		"another method":     do(http.MethodPost, s.approvalPath(), pagetest.PostHeaders(s.secret), "{}"),
		"a revert of its id": do(http.MethodGet, "/api/v1/reverts/"+s.agent.id.String(), pagetest.Headers(s.secret), ""),
	}
	for name, r := range sameAsUnknown {
		require.Equal(t, unknown, r, name)
	}

	withHeader := pagetest.Headers(s.secret)
	withHeader["cookie"] = "a=b"
	r := do(http.MethodGet, s.approvalPath(), withHeader, "")
	require.Equal(t, http.StatusBadRequest, r.Status)
	require.Contains(t, r.Body, `"code":"INVALID_ARGUMENT"`)

	foreign := pagetest.PostHeaders(s.secret)
	foreign["origin"] = "https://evil.example"
	require.Equal(t, http.StatusForbidden, do(http.MethodGet, s.approvalPath(), foreign, "").Status)
	require.Equal(t, http.StatusForbidden, do(http.MethodPost, s.approvalPath()+"/approve", foreign, "{}").Status)

	require.Equal(t, http.StatusUnsupportedMediaType, do(http.MethodPost, s.approvalPath()+"/approve", pagetest.Headers(s.secret), "{}").Status)
	r, err = p.Do(ctx, http.MethodPost, s.approvalPath()+"/approve", pagetest.PostHeaders(s.secret), strings.Repeat("a", 20<<10), 4096)
	require.NoError(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, r.Status)
	require.Equal(t, http.StatusBadRequest, do(http.MethodPost, s.approvalPath()+"/approve", pagetest.PostHeaders(s.secret), "{}").Status)
	require.False(t, s.agent.isApproved())

	// Refusals leave the session usable.
	require.Equal(t, http.StatusOK, do(http.MethodGet, s.approvalPath(), pagetest.Headers(s.secret), "").Status)
}

// Reissuing the item's link revokes the old one: its open sessions end with
// LINK_REFUSED, and its secret opens no new session. The new link works.
func TestVaultSessionEndsWhenItsLinkIsRevoked(t *testing.T) {
	t.Parallel()
	s := newVaultSession(t)
	p := s.open(t)
	ctx := waitCtx(t)
	r, err := p.Do(ctx, http.MethodGet, s.approvalPath(), pagetest.Headers(s.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)

	newSecret, token, err := s.store.IssueRelay(s.agent.id, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, websocket.StatusCode(channel.ErrLinkRefused), p.Closed(ctx))

	old, err := pagetest.Dial(ctx, s.v.URL(), s.keys.Token)
	if err == nil {
		err = old.Handshake(ctx, s.keys)
	}
	require.Error(t, err, "the old link opens no session")

	// The new link opens once registered.
	require.NoError(t, s.client.Register(ctx, token, time.Now().Add(time.Hour)))
	keys, err := channel.DeriveLink(newSecret)
	require.NoError(t, err)
	fresh, err := pagetest.Open(ctx, s.v.URL(), keys)
	require.NoError(t, err)
	t.Cleanup(fresh.Close)
	r, err = fresh.Do(ctx, http.MethodGet, s.approvalPath(), pagetest.Headers(newSecret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)
	r, err = fresh.Do(ctx, http.MethodGet, s.approvalPath(), pagetest.Headers(s.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, r.Status, "the old secret is refused inside a session too")
}

// The engine resolves a session's token the same way whether it holds the
// token or not (the uniform dead-token path): an unknown token and a live
// token with a wrong psk take the same work through the lookup and the tag
// check, so a probe cannot tell them apart by time.
func TestVaultSessionDeadTokenTiming(t *testing.T) {
	t.Parallel()
	relay := linksvc.NewRegistry(quietLog())
	for range 2 {
		store := links.NewSecrets(time.Now, rand.Reader)
		relay.Add("bot", store, func(channel.LinkToken) {})
		for range 50 {
			_, _, err := store.IssueRelay(uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour))
			require.NoError(t, err)
		}
	}
	live := relay.Live()[17].Token
	wrong := channel.LinkKeys{Token: live}
	_, err := rand.Read(wrong.PSK[:])
	require.NoError(t, err)
	dead := channel.LinkKeys{}
	_, err = rand.Read(dead.Token[:])
	require.NoError(t, err)
	_, err = rand.Read(dead.PSK[:])
	require.NoError(t, err)

	refuse := func(keys channel.LinkKeys) time.Duration {
		_, msg, err := channel.WriteHello(channel.TransportRelay, keys)
		require.NoError(t, err)
		token := keys.Token
		lookup := func(t channel.LinkToken) (channel.PSK, bool) {
			l, ok := vaultLinks{relay}.Session(t)
			return l.PSK, ok
		}
		start := time.Now()
		_, err = channel.ReadHello(msg, channel.HelloCheck{Transport: channel.TransportRelay, SessionToken: &token, Lookup: lookup})
		elapsed := time.Since(start)
		require.ErrorIs(t, err, channel.ErrLinkRefused)
		return elapsed
	}
	const runs = 400
	wrongTimes, deadTimes := make([]time.Duration, 0, runs), make([]time.Duration, 0, runs)
	for range runs {
		wrongTimes = append(wrongTimes, refuse(wrong))
		deadTimes = append(deadTimes, refuse(dead))
	}
	median := func(d []time.Duration) time.Duration {
		slices.Sort(d)
		return d[len(d)/2]
	}
	w, d := median(wrongTimes), median(deadTimes)
	require.Less(t, w, 2*d, "a live token with a wrong psk (%s) takes no longer than a dead one (%s)", w, d)
	require.Less(t, d, 2*w, "a dead token (%s) takes no longer than a live one with a wrong psk (%s)", d, w)
}
