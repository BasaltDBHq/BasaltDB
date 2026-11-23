package vault_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// hostile is a Vault's tamper hook that alters a session as edit says.
// edit sees each session message with its index among the messages of its
// session and direction (message 1 and message 2 are index 0), and what the
// Vault received before it.
type hostile struct {
	mu   sync.Mutex
	seen map[[2]any]int
	sids []vaulttest.SID
	kept []vaulttest.Message
	edit func(h *hostile, m vaulttest.Message, n int) []vaulttest.Delivery
}

func (h *hostile) tamper(m vaulttest.Message) []vaulttest.Delivery {
	h.mu.Lock()
	defer h.mu.Unlock()
	m.Data = slices.Clone(m.Data)
	key := [2]any{m.Session.SID, m.Dir}
	n := h.seen[key]
	h.seen[key]++
	if n == 0 && m.Dir == vaulttest.ToEngine {
		h.sids = append(h.sids, m.Session.SID)
	}
	out := h.edit(h, m, n)
	h.kept = append(h.kept, m)
	return out
}

func forward(m vaulttest.Message) []vaulttest.Delivery {
	return []vaulttest.Delivery{vaulttest.Forward(m)}
}

// newHostileEngine is newSessionEngine behind a Vault that alters sessions
// as edit says.
func newHostileEngine(t *testing.T, edit func(h *hostile, m vaulttest.Message, n int) []vaulttest.Delivery) *sessionEngine {
	t.Helper()
	h := &hostile{seen: map[[2]any]int{}, edit: edit}
	v := vaulttest.New(vaulttest.Options{Tamper: h.tamper})
	t.Cleanup(v.Close)
	e := &sessionEngine{v: v, keys: newKeys(t), links: &fakeLinks{m: map[channel.LinkToken]vault.SessionLink{}}, pages: &echoPages{}}
	opts := fastOptions(v.URL(), e.keys)
	opts.SessionLinks, opts.Pages = e.links, e.pages
	e.c = newClient(t, opts)
	run(t, e.c)
	require.Eventually(t, e.c.Connected, waitFor, tick)
	return e
}

func (e *sessionEngine) ran() int {
	e.pages.mu.Lock()
	defer e.pages.mu.Unlock()
	return len(e.pages.got)
}

// Every way a hostile Vault can alter the page's frames on their way to an
// honest engine ends the session with FRAME_INVALID, and no altered frame
// runs a request: tampered, duplicated, replayed, reordered, reflected back
// to the engine, or spliced in from another session.
func TestHostileVaultFramesToTheEngine(t *testing.T) {
	t.Parallel()
	frameTo := func(dir vaulttest.Direction, at int, f func(h *hostile, m vaulttest.Message) []vaulttest.Delivery) func(*hostile, vaulttest.Message, int) []vaulttest.Delivery {
		return func(h *hostile, m vaulttest.Message, n int) []vaulttest.Delivery {
			if m.Dir == dir && n == at {
				return f(h, m)
			}
			return forward(m)
		}
	}
	cases := map[string]struct {
		edit func(*hostile, vaulttest.Message, int) []vaulttest.Delivery
		// requests is how many requests the page sends, chunk how its
		// body is cut (0: one frame each).
		requests, chunk int
		// ran is how many requests the engine runs: only the page's own,
		// never an altered copy. atMost: the page's own request may also
		// not run, when the altered copy right behind it ends the session
		// before the engine's worker takes the request.
		ran    int
		atMost bool
	}{
		"a tampered frame": {requests: 1, ran: 0, edit: frameTo(vaulttest.ToEngine, 1, func(_ *hostile, m vaulttest.Message) []vaulttest.Delivery {
			d := vaulttest.Forward(m)
			d.Data[len(d.Data)/2] ^= 0x01
			return []vaulttest.Delivery{d}
		})},
		"a duplicated frame": {requests: 1, ran: 1, atMost: true, edit: frameTo(vaulttest.ToEngine, 1, func(_ *hostile, m vaulttest.Message) []vaulttest.Delivery {
			return []vaulttest.Delivery{vaulttest.Forward(m), vaulttest.Forward(m)}
		})},
		"a replayed frame": {requests: 2, ran: 1, edit: frameTo(vaulttest.ToEngine, 2, func(h *hostile, m vaulttest.Message) []vaulttest.Delivery {
			for _, k := range h.kept {
				if k.Session.SID == m.Session.SID && k.Dir == vaulttest.ToEngine && k.Data[1] == 0x03 {
					return []vaulttest.Delivery{vaulttest.Forward(k)}
				}
			}
			return forward(m)
		})},
		"reordered frames": {requests: 1, chunk: 100, ran: 0, edit: func(h *hostile, m vaulttest.Message, n int) []vaulttest.Delivery {
			switch {
			case m.Dir == vaulttest.ToEngine && n == 1:
				return nil // held back
			case m.Dir == vaulttest.ToEngine && n == 2:
				held := h.kept[len(h.kept)-1]
				return []vaulttest.Delivery{vaulttest.Forward(m), vaulttest.Forward(held)}
			}
			return forward(m)
		}},
		"the engine's own frame reflected back to it": {requests: 1, ran: 1, edit: frameTo(vaulttest.ToPage, 1, func(_ *hostile, m vaulttest.Message) []vaulttest.Delivery {
			return []vaulttest.Delivery{{SID: m.Session.SID, Dir: vaulttest.ToEngine, Data: m.Data}}
		})},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newHostileEngine(t, c.edit)
			l := newLink(t)
			e.hold(t, l, time.Now().Add(time.Hour))
			p := e.open(t, l)
			ctx, cancel := context.WithTimeout(context.Background(), waitFor)
			defer cancel()
			body := ""
			if c.chunk > 0 {
				body = `{"pad":"` + strings.Repeat("x", 3*c.chunk) + `"}`
			}
			var err error
			for range c.requests {
				method := http.MethodGet
				headers := pagetest.Headers(l.secret)
				if body != "" {
					method, headers = http.MethodPost, pagetest.PostHeaders(l.secret)
				}
				if _, err = p.Do(ctx, method, "/x", headers, body, c.chunk); err != nil {
					break
				}
			}
			got := pageClosed(t, p)
			if err != nil && websocket.CloseStatus(err) != -1 {
				got = websocket.CloseStatus(err)
			}
			require.Equal(t, code(channel.ErrFrameInvalid), got)
			if c.atMost {
				require.LessOrEqual(t, e.ran(), c.ran, "requests the engine ran")
			} else {
				require.Equal(t, c.ran, e.ran(), "requests the engine ran")
			}
		})
	}
}

// A frame taken from one session and delivered into another of the same
// link does not open there: that session closes with FRAME_INVALID, and
// the request it carried runs nowhere.
func TestHostileVaultSplicesAFrameIntoAnotherSession(t *testing.T) {
	t.Parallel()
	e := newHostileEngine(t, func(h *hostile, m vaulttest.Message, n int) []vaulttest.Delivery {
		if m.Dir == vaulttest.ToEngine && n == 1 && len(h.sids) == 2 && m.Session.SID == h.sids[1] {
			return []vaulttest.Delivery{{SID: h.sids[0], Dir: vaulttest.ToEngine, Data: m.Data}}
		}
		return forward(m)
	})
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	victim := e.open(t, l)
	sender := e.open(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := sender.Do(ctx, http.MethodGet, "/x", pagetest.Headers(l.secret), "", 0)
	require.Error(t, err, "the sender's request never reached its own session")
	require.Equal(t, code(channel.ErrFrameInvalid), pageClosed(t, victim))
	require.Zero(t, e.ran())
}

// A wrong secret, an expired link, a revoked link and a token the engine
// never held all end the same way: the page's socket closes with
// LINK_REFUSED, and nothing comes before the close (no message 2, no byte).
func TestDeadLinksGetNothingButLinkRefused(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	live, expired, revoked, unknown := newLink(t), newLink(t), newLink(t), newLink(t)
	for _, l := range []link{live, expired, revoked} {
		e.hold(t, l, time.Now().Add(time.Hour))
	}
	e.links.mu.Lock()
	x := e.links.m[expired.keys.Token]
	x.ExpiresAt = time.Now().Add(-time.Second)
	e.links.m[expired.keys.Token] = x
	e.links.mu.Unlock()
	e.links.drop(revoked.keys.Token)
	// The Vault routes these tokens to this engine as if it held them.
	e.v.Bind(unknown.keys.Token.Wire(), e.keys.EngineID(), time.Now().Add(time.Hour))
	e.v.Bind(revoked.keys.Token.Wire(), e.keys.EngineID(), time.Now().Add(time.Hour))
	wrong := live.keys
	wrong.PSK[0] ^= 0xff

	for name, c := range map[string]struct {
		token channel.LinkToken
		keys  channel.LinkKeys
	}{
		"a wrong secret":                {live.keys.Token, wrong},
		"an expired link":               {expired.keys.Token, expired.keys},
		"a revoked link":                {revoked.keys.Token, revoked.keys},
		"a token the engine never held": {unknown.keys.Token, unknown.keys},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := ctxWait(t)
			p, err := pagetest.Dial(ctx, e.v.URL(), c.token)
			require.NoError(t, err)
			require.NoError(t, p.SendRaw(ctx, helloFor(c.keys)(t)))
			data, err := p.ReadRaw(ctx)
			require.Error(t, err, "nothing before the close: %x", data)
			require.Nil(t, data)
			require.Equal(t, code(channel.ErrLinkRefused), websocket.CloseStatus(err))
		})
	}
	e.open(t, live)
	require.Zero(t, e.ran())
}

// Message 1 is exactly 99 bytes: one byte more or less is PROTOCOL, before
// the engine looks anything up.
func TestMessageOneOfAnotherLength(t *testing.T) {
	t.Parallel()
	e := newSessionEngine(t, nil)
	l := newLink(t)
	e.hold(t, l, time.Now().Add(time.Hour))
	for name, edit := range map[string]func([]byte) []byte{
		"100 bytes": func(m []byte) []byte { return append(m, 0) },
		"98 bytes":  func(m []byte) []byte { return m[:len(m)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := ctxWait(t)
			p, err := pagetest.Dial(ctx, e.v.URL(), l.keys.Token)
			require.NoError(t, err)
			msg := helloFor(l.keys)(t)
			require.Len(t, msg, channel.Message1Len)
			require.NoError(t, p.SendRaw(ctx, edit(msg)))
			require.Equal(t, code(channel.ErrProtocol), pageClosed(t, p))
		})
	}
}
