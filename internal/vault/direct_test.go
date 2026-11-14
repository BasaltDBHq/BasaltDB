package vault_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// directEngine serves the direct transport's sessions on a test listener.
type directEngine struct {
	d     *vault.Direct
	url   string
	links *fakeLinks
	pages *echoPages
}

func newDirectEngine(t *testing.T, tune func(*vault.DirectOptions), admit func(context.Context, vault.SessionLink) channel.CloseError) *directEngine {
	t.Helper()
	e := &directEngine{links: &fakeLinks{m: map[channel.LinkToken]vault.SessionLink{}}, pages: &echoPages{}}
	o := vault.DirectOptions{Keys: newKeys(t), SessionLinks: e.links, Pages: e.pages}
	if tune != nil {
		tune(&o)
	}
	e.d = vault.NewDirect(o)
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"portal.basaltvault.app"}})
		if err != nil {
			return
		}
		e.d.Serve(ctx, ws, admit)
	}))
	t.Cleanup(func() { cancel(); srv.Close() })
	e.url = "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/session"
	return e
}

func (e *directEngine) hold(l link) {
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	e.links.m[l.keys.Token] = vault.SessionLink{Token: l.keys.Token, Agent: "bot", Item: l.item, PSK: l.keys.PSK, ExpiresAt: time.Now().Add(time.Hour)}
}

func (e *directEngine) dial(t *testing.T) *pagetest.Page {
	t.Helper()
	p, err := pagetest.DialDirect(ctxWait(t), e.url, nil)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}

// A page reaches the engine's own listener and runs the same session, with
// DIRECT in the prologue.
func TestDirectSessionAnswersRequests(t *testing.T) {
	t.Parallel()
	e := newDirectEngine(t, nil, nil)
	l := newLink(t)
	e.hold(l)
	p := e.dial(t)
	require.NoError(t, p.Handshake(ctxWait(t), l.keys))
	r, err := p.Do(ctxWait(t), http.MethodGet, "/api/v1/approvals/x", pagetest.Headers(l.secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)
	require.Contains(t, r.Body, l.item.String())

	// The engine ends it when the link is revoked.
	e.d.EndLink(l.keys.Token)
	require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, p))
}

func TestDirectSessionRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a link the engine does not hold", func(t *testing.T) {
		t.Parallel()
		e := newDirectEngine(t, nil, nil)
		p := e.dial(t)
		require.Equal(t, code(channel.ErrLinkRefused), failedWith(t, p, p.Handshake(ctxWait(t), newLink(t).keys)))
	})
	t.Run("a relay handshake on the direct socket", func(t *testing.T) {
		t.Parallel()
		e := newDirectEngine(t, nil, nil)
		l := newLink(t)
		e.hold(l)
		p := e.dial(t)
		_, m1, err := channel.WriteHello(channel.TransportRelay, l.keys)
		require.NoError(t, err)
		require.NoError(t, p.SendRaw(ctxWait(t), m1))
		require.Equal(t, code(channel.ErrLinkRefused), pageClosed(t, p), "the prologue binds the transport")
	})
	t.Run("revoked in the agent's database", func(t *testing.T) {
		t.Parallel()
		var admitted vault.SessionLink
		e := newDirectEngine(t, nil, func(_ context.Context, l vault.SessionLink) channel.CloseError {
			admitted = l
			return channel.ErrEngineRevoked
		})
		l := newLink(t)
		e.hold(l)
		p := e.dial(t)
		require.Equal(t, code(channel.ErrEngineRevoked), failedWith(t, p, p.Handshake(ctxWait(t), l.keys)))
		require.Equal(t, "bot", admitted.Agent)
	})
	t.Run("a text message", func(t *testing.T) {
		t.Parallel()
		e := newDirectEngine(t, nil, nil)
		ws, resp, err := websocket.Dial(ctxWait(t), e.url, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {"https://portal.basaltvault.app"}}})
		require.NoError(t, err)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		require.NoError(t, ws.Write(ctxWait(t), websocket.MessageText, []byte("hello")))
		_, _, err = ws.Read(ctxWait(t))
		require.Equal(t, code(channel.ErrProtocol), websocket.CloseStatus(err))
	})
	t.Run("no message 1 in time", func(t *testing.T) {
		t.Parallel()
		e := newDirectEngine(t, func(o *vault.DirectOptions) { o.Message1Timeout = 50 * time.Millisecond }, nil)
		p := e.dial(t)
		require.Equal(t, code(channel.ErrTimeout), pageClosed(t, p))
	})
}
