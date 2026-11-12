package vault_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// fakeLinks are the engine's relay links for session tests.
type fakeLinks struct {
	mu sync.Mutex
	m  map[channel.LinkToken]vault.SessionLink
}

func (f *fakeLinks) Session(token channel.LinkToken) (vault.SessionLink, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.m[token]
	if !ok || !time.Now().Before(l.ExpiresAt) {
		return vault.SessionLink{}, false
	}
	return l, true
}

func (f *fakeLinks) drop(token channel.LinkToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, token)
}

// link is a relay link the test holds: its secret and the keys from it.
type link struct {
	secret string
	keys   channel.LinkKeys
	item   uuid.UUID
}

func newLink(t *testing.T) link {
	t.Helper()
	raw := make([]byte, channel.SecretLen)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	return link{secret: secret, keys: keys, item: uuid.Must(uuid.NewV7())}
}

// echoPages answer every request with what they received; "/big" gets a
// body that takes several frames. With gate set, each request waits for it.
type echoPages struct {
	gate chan struct{}
	mu   sync.Mutex
	got  []vault.Request
}

// echo is echoPages' answer.
type echo struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	BodyLen int               `json:"bodyLen"`
	Item    string            `json:"item"`
}

// bigBody needs JSON escaping and holds runes of several bytes, so the
// engine must cut it on rune boundaries and by its escaped size.
var bigBody = strings.Repeat("é\"\n<x>€", 15000)

func (p *echoPages) Dispatch(ctx context.Context, l vault.SessionLink, req vault.Request) vault.Response {
	p.mu.Lock()
	p.got = append(p.got, req)
	p.mu.Unlock()
	if p.gate != nil {
		select {
		case <-p.gate:
		case <-ctx.Done():
		}
	}
	if req.Path == "/big" {
		return vault.Response{Status: http.StatusOK, ContentType: "text/plain", Body: []byte(bigBody)}
	}
	body, err := json.Marshal(echo{Method: req.Method, Path: req.Path, Headers: req.Headers, BodyLen: len(req.Body), Item: l.Item.String()})
	if err != nil {
		return vault.Response{Status: http.StatusInternalServerError}
	}
	return vault.Response{Status: http.StatusOK, ContentType: "application/json", Body: body}
}

// sessionEngine is an engine connected to a fake Vault, serving sessions
// with links and pages.
type sessionEngine struct {
	v     *vaulttest.Vault
	c     *vault.Client
	keys  *channel.EngineKeys
	links *fakeLinks
	pages *echoPages
}

func newSessionEngine(t *testing.T, tune func(*vault.Options)) *sessionEngine {
	t.Helper()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	e := &sessionEngine{v: v, keys: newKeys(t), links: &fakeLinks{m: map[channel.LinkToken]vault.SessionLink{}}, pages: &echoPages{}}
	opts := fastOptions(v.URL(), e.keys)
	opts.SessionLinks, opts.Pages = e.links, e.pages
	if tune != nil {
		tune(&opts)
	}
	e.c = newClient(t, opts)
	run(t, e.c)
	require.Eventually(t, e.c.Connected, waitFor, tick)
	return e
}

// hold makes the engine hold l until expires and registers it at the Vault.
func (e *sessionEngine) hold(t *testing.T, l link, expires time.Time) {
	t.Helper()
	e.links.mu.Lock()
	e.links.m[l.keys.Token] = vault.SessionLink{Token: l.keys.Token, Item: l.item, PSK: l.keys.PSK, ExpiresAt: expires}
	e.links.mu.Unlock()
	require.NoError(t, e.c.Register(context.Background(), l.keys.Token, expires))
}

func (e *sessionEngine) open(t *testing.T, l link) *pagetest.Page {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	p, err := pagetest.Open(ctx, e.v.URL(), l.keys)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}

// pageClosed is the close code of a page whose handshake or request failed.
func pageClosed(t *testing.T, p *pagetest.Page) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	return p.Closed(ctx)
}

// failedWith is the close code of a page whose handshake or request failed
// with err: err's own, or the one it reads next.
func failedWith(t *testing.T, p *pagetest.Page, err error) websocket.StatusCode {
	t.Helper()
	require.Error(t, err)
	if c := websocket.CloseStatus(err); c != -1 {
		return c
	}
	return pageClosed(t, p)
}

func code(c channel.CloseError) websocket.StatusCode { return websocket.StatusCode(c) }

func ctxWait(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	t.Cleanup(cancel)
	return ctx
}

func TestSessionAnswersRequests(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	p := e.open(t, l)
	require.Equal(t, e.keys.EngineID(), p.Welcome.EngineID, "message 2 is signed by the engine's key")
	ctx := ctxWait(t)

	r, err := p.Do(ctx, http.MethodGet, "/api/v1/approvals/x", pagetest.Headers(l.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)
	require.Equal(t, "application/json", r.ContentType)
	var got echo
	require.NoError(t, json.Unmarshal([]byte(r.Body), &got))
	require.Equal(t, echo{Method: http.MethodGet, Path: "/api/v1/approvals/x", Headers: pagetest.Headers(l.secret), Item: l.item.String()}, got)

	// A body in CONTINUE frames is put together; past 16 KiB the engine
	// keeps one byte more and no further.
	r, err = p.Do(ctx, http.MethodPost, "/p", pagetest.PostHeaders(l.secret), strings.Repeat("a", 40000), 3000)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(r.Body), &got))
	require.Equal(t, vault.MaxRequestBody+1, got.BodyLen)
	r, err = p.Do(ctx, http.MethodPost, "/p", pagetest.PostHeaders(l.secret), strings.Repeat("b", 9000), 1000)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(r.Body), &got))
	require.Equal(t, 9000, got.BodyLen)

	// A response larger than a frame continues in CONTINUE frames.
	r, err = p.Do(ctx, http.MethodGet, "/big", pagetest.Headers(l.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, bigBody, r.Body)
	require.Greater(t, r.Frames, 3)
}

// A token the engine does not hold, a held token with a wrong psk, an
// expired link and an invalid ephemeral key are all LINK_REFUSED, alike.
func TestSessionRefusesDeadTokensAlike(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	live, expired, unknown := newLink(t), newLink(t), newLink(t)
	e.hold(t, live, time.Now().Add(time.Hour))
	e.hold(t, expired, time.Now().Add(time.Hour))
	e.links.mu.Lock()
	l := e.links.m[expired.keys.Token]
	l.ExpiresAt = time.Now().Add(-time.Second)
	e.links.m[expired.keys.Token] = l
	e.links.mu.Unlock()
	// The Vault routes the unknown token to this engine as if it held it.
	e.v.Bind(unknown.keys.Token.String(), e.keys.EngineID(), time.Now().Add(time.Hour))

	wrongPSK := live.keys
	_, err := rand.Read(wrongPSK.PSK[:])
	require.NoError(t, err)
	badPoint := func(t *testing.T) []byte {
		_, msg, err := channel.WriteHello(channel.TransportRelay, live.keys)
		require.NoError(t, err)
		msg[2+channel.LinkTokenLen+1] ^= 0xff // off the curve, and the tag no longer matches
		return msg
	}
	cases := map[string]struct {
		token channel.LinkToken
		msg1  func(t *testing.T) []byte
	}{
		"a token the engine does not hold": {unknown.keys.Token, helloFor(unknown.keys)},
		"a wrong psk":                      {live.keys.Token, helloFor(wrongPSK)},
		"an expired link":                  {expired.keys.Token, helloFor(expired.keys)},
		"an invalid ephemeral key":         {live.keys.Token, badPoint},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := ctxWait(t)
			p, err := pagetest.Dial(ctx, e.v.URL(), tc.token)
			require.NoError(t, err)
			require.NoError(t, p.SendRaw(ctx, tc.msg1(t)))
			require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, p))
		})
	}
	// The live link still opens.
	e.open(t, live)
}

func helloFor(keys channel.LinkKeys) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		_, msg, err := channel.WriteHello(channel.TransportRelay, keys)
		require.NoError(t, err)
		return msg
	}
}

// Frames that do not open with the next counter, or whose content is not
// one of the schema's shapes, end the session.
func TestSessionRefusesBadFrames(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	content := func(v any) func(*testing.T, *pagetest.Page) []byte {
		return func(t *testing.T, p *pagetest.Page) []byte {
			raw, ok := v.(string)
			if !ok {
				b, err := json.Marshal(v)
				require.NoError(t, err)
				raw = string(b)
			}
			frame, err := p.Seal([]byte(raw))
			require.NoError(t, err)
			return frame
		}
	}
	req := pagetest.Request{Type: "REQUEST", ID: 1, Method: "GET", Path: "/x", Headers: pagetest.Headers(l.secret), More: false}
	cases := map[string]struct {
		frame func(*testing.T, *pagetest.Page) []byte
		want  channel.CloseError
	}{
		"garbage":           {func(*testing.T, *pagetest.Page) []byte { return append([]byte{1, 3}, make([]byte, 1040)...) }, channel.ErrFrameInvalid},
		"another version":   {func(*testing.T, *pagetest.Page) []byte { return append([]byte{2, 3}, make([]byte, 1040)...) }, channel.ErrUnsupportedVersion},
		"not a frame":       {func(*testing.T, *pagetest.Page) []byte { return append([]byte{1, 1}, make([]byte, 1040)...) }, channel.ErrProtocol},
		"not JSON":          {content("REQUEST"), channel.ErrProtocol},
		"a RESPONSE":        {content(map[string]any{"type": "RESPONSE", "id": 1, "status": 200, "headers": map[string]string{}, "body": "", "more": false}), channel.ErrProtocol},
		"a lone CONTINUE":   {content(pagetest.Continue{Type: "CONTINUE", ID: 1}), channel.ErrProtocol},
		"an unknown field":  {content(`{"type":"REQUEST","id":1,"method":"GET","path":"/x","headers":{},"body":"","more":false,"x":1}`), channel.ErrProtocol},
		"no headers":        {content(`{"type":"REQUEST","id":1,"method":"GET","path":"/x","body":"","more":false}`), channel.ErrProtocol},
		"trailing data":     {content(`{"type":"REQUEST","id":1,"method":"GET","path":"/x","headers":{},"body":"","more":false} {}`), channel.ErrProtocol},
		"an id out of turn": {content(pagetest.Request{Type: "REQUEST", ID: 2, Method: "GET", Path: "/x", Headers: req.Headers}), channel.ErrProtocol},
		"a replayed frame": {func(t *testing.T, p *pagetest.Page) []byte {
			frame := content(req)(t, p)
			require.NoError(t, p.SendRaw(context.Background(), frame))
			return frame
		}, channel.ErrFrameInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := e.open(t, l)
			require.NoError(t, p.SendRaw(ctxWait(t), tc.frame(t, p)))
			require.Equal(t, code(tc.want), pageClosed(t, p))
		})
	}
}

// A frame over its limit never reaches the engine as a frame: the Vault
// refuses it, and a ROUTE over the engine socket's limit closes that socket
// with TOO_LARGE before it is read in.
func TestSessionOversizeFrames(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))

	p := e.open(t, l)
	require.NoError(t, p.SendRaw(ctxWait(t), append([]byte{1, 3}, make([]byte, channel.FrameMax-1)...)))
	require.Equal(t, code(channel.ErrTooLarge), pageClosed(t, p), "the Vault refuses a frame over 32 786 bytes")

	// A frame of exactly the limit is read, and refused only for its bytes.
	p = e.open(t, l)
	require.NoError(t, p.SendRaw(ctxWait(t), append([]byte{1, 3}, make([]byte, channel.FrameMax-2)...)))
	require.Equal(t, code(channel.ErrFrameInvalid), pageClosed(t, p))

	// A hostile Vault's oversize ROUTE for an open session.
	p = e.open(t, l)
	require.Eventually(t, func() bool { return len(e.v.Sessions()) == 1 }, waitFor, tick)
	sid := e.v.Sessions()[0].SID
	require.NoError(t, e.v.InjectRaw(e.keys.EngineID(), websocket.MessageBinary, vaulttest.Route(sid, make([]byte, channel.FrameMax+1))))
	require.Equal(t, code(channel.ErrEngineOffline), pageClosed(t, p), "the engine's socket ended, and its sessions with it")
	require.Eventually(t, e.c.Connected, waitFor, tick, "the engine dials again")
}

func TestSessionLimits(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)

	t.Run("sessions per link", func(t *testing.T) {
		t.Parallel()
		l := newLink(t)
		e.hold(t, l, time.Now().Add(time.Hour))
		pages := make([]*pagetest.Page, 0, vault.MaxSessionsPerLink)
		for range vault.MaxSessionsPerLink {
			pages = append(pages, e.open(t, l))
		}
		ctx := ctxWait(t)
		p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
		require.NoError(t, err)
		err = p.Handshake(ctx, l.keys)
		require.Equal(t, code(channel.ErrSessionLimit), failedWith(t, p, err))
		// One ends: a new session opens.
		pages[0].Close()
		require.Eventually(t, func() bool {
			p, err := pagetest.Open(ctx, e.v.URL(), l.keys)
			if err != nil {
				return false
			}
			t.Cleanup(p.Close)
			return true
		}, waitFor, 20*time.Millisecond)
	})

	t.Run("handshakes per link, refused ones counted", func(t *testing.T) {
		t.Parallel()
		l := newLink(t)
		e.hold(t, l, time.Now().Add(time.Hour))
		wrong := l.keys
		_, err := rand.Read(wrong.PSK[:])
		require.NoError(t, err)
		ctx := ctxWait(t)
		for range vault.HandshakesPerLink {
			p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
			require.NoError(t, err)
			require.NoError(t, p.SendRaw(ctx, helloFor(wrong)(t)))
			require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, p))
		}
		p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
		require.NoError(t, err)
		err = p.Handshake(ctx, l.keys)
		require.Equal(t, code(channel.ErrRateLimited), failedWith(t, p, err))
	})

	t.Run("requests per session", func(t *testing.T) {
		t.Parallel()
		l := newLink(t)
		e.hold(t, l, time.Now().Add(time.Hour))
		p := e.open(t, l)
		ctx := ctxWait(t)
		for range vault.MaxRequests {
			r, err := p.Do(ctx, http.MethodGet, "/x", pagetest.Headers(l.secret), "", 0)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.Status)
		}
		_, err := p.Do(ctx, http.MethodGet, "/x", pagetest.Headers(l.secret), "", 0)
		require.Equal(t, code(channel.ErrRateLimited), failedWith(t, p, err))
	})
}

// One request in flight: a second REQUEST before the response ends the
// session with PROTOCOL.
func TestSessionOneRequestInFlight(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	e.pages.gate = make(chan struct{})
	t.Cleanup(func() { close(e.pages.gate) })
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	p := e.open(t, l)
	ctx := ctxWait(t)
	for id := 1; id <= 2; id++ {
		require.NoError(t, p.SendJSON(ctx, pagetest.Request{Type: "REQUEST", ID: id, Method: "GET", Path: "/x", Headers: pagetest.Headers(l.secret)}))
	}
	require.Equal(t, code(channel.ErrProtocol), pageClosed(t, p))
}

func TestSessionTimeouts(t *testing.T) {
	t.Parallel()
	t.Run("idle", func(t *testing.T) {
		t.Parallel()
		e := newSessionEngine(t, func(o *vault.Options) { o.IdleTimeout = 500 * time.Millisecond })
		l := newLink(t)
		e.hold(t, l, time.Now().Add(time.Hour))
		p := e.open(t, l)
		ctx := ctxWait(t)
		// Frames keep it open past the idle timeout.
		for range 8 {
			time.Sleep(100 * time.Millisecond)
			_, err := p.Do(ctx, http.MethodGet, "/x", pagetest.Headers(l.secret), "", 0)
			require.NoError(t, err)
		}
		start := time.Now()
		require.Equal(t, code(channel.ErrTimeout), pageClosed(t, p))
		require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond)
	})
	t.Run("lifetime", func(t *testing.T) {
		t.Parallel()
		e := newSessionEngine(t, func(o *vault.Options) { o.SessionLifetime = 200 * time.Millisecond })
		l := newLink(t)
		e.hold(t, l, time.Now().Add(time.Hour))
		p := e.open(t, l)
		start := time.Now()
		ctx := ctxWait(t)
		var err error
		for err == nil {
			time.Sleep(20 * time.Millisecond)
			_, err = p.Do(ctx, http.MethodGet, "/x", pagetest.Headers(l.secret), "", 0)
		}
		require.Equal(t, code(channel.ErrTimeout), failedWith(t, p, err))
		require.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)
	})
	t.Run("never past the link's expiry", func(t *testing.T) {
		t.Parallel()
		e := newSessionEngine(t, nil)
		l := newLink(t)
		e.hold(t, l, time.Now().Add(1500*time.Millisecond))
		p := e.open(t, l)
		require.Equal(t, code(channel.ErrTimeout), pageClosed(t, p))
	})
}

// A link revoked while its sessions are open ends them with LINK_REFUSED,
// and a new session on it is refused.
func TestRevokedLinkEndsItsSessions(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	l, other := newLink(t), newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	e.hold(t, other, time.Now().Add(time.Hour))
	a, b, c := e.open(t, l), e.open(t, l), e.open(t, other)

	e.links.drop(l.keys.Token)
	e.c.Unregister(l.keys.Token)
	require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, a))
	require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, b))

	// Another link's session is untouched.
	r, err := c.Do(ctxWait(t), http.MethodGet, "/x", pagetest.Headers(other.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)

	// The Vault no longer routes the token.
	ctx := ctxWait(t)
	p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
	if err == nil {
		err = p.Handshake(ctx, l.keys)
	}
	require.Error(t, err)
}

// Without pages to answer them, sessions are refused at message 1 even for
// a link the engine holds.
func TestNoPagesRefusesSessions(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, func(o *vault.Options) { o.Pages = nil })
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	ctx := ctxWait(t)
	p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
	require.NoError(t, err)
	err = p.Handshake(ctx, l.keys)
	require.Error(t, err)
	require.Equal(t, code(channel.ErrLinkRefused), failedWith(t, p, err))
}
