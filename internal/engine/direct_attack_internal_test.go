package engine

// Attacks on the direct transport behind a tunnel (CONTRACT.md, Direct
// transport): a tunnel or host that rewrites Host or Origin, a session over
// another agent's address, a replayed handshake, a revoked engine, and
// floods of sockets, upgrades and slow headers on the listener.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// countPages answers like okPages and counts the requests that reached
// the engine's pages.
type countPages struct{ n atomic.Int32 }

func (c *countPages) Dispatch(ctx context.Context, l vault.SessionLink, r vault.Request) vault.Response {
	c.n.Add(1)
	return okPages{}.Dispatch(ctx, l, r)
}

// addAgent serves another agent, name, whose database is its own: the
// engine reads that agent's record there. It returns the database.
func (f *directFixture) addAgent(t *testing.T, name string) *guardtest.DB {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, name, []string{"public.leads"}, []string{"public.leads"})
	f.records.add(name, agentPool(t, a.URL))
	return d
}

// holdLinkOf holds a link of agent, as holdLink does for bot.
func (f *directFixture) holdLinkOf(t *testing.T, agent string) (channel.LinkKeys, string) {
	t.Helper()
	keys, secret, _ := f.holdLink(t)
	f.links.mu.Lock()
	l := f.links.m[keys.Token]
	l.Agent = agent
	f.links.m[keys.Token] = l
	f.links.mu.Unlock()
	return keys, secret
}

func (f *directFixture) dialHost(t *testing.T, host string) *pagetest.Page {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := pagetest.DialDirect(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http")+"/v1/session", http.Header{"Host": {host}})
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}

// upgrade asks for a WebSocket upgrade of /v1/session with host and
// origin (none when empty) and extra headers, and returns the status.
func (f *directFixture) upgrade(t *testing.T, host, origin string, extra http.Header) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	var b strings.Builder
	fmt.Fprintf(&b, "GET /v1/session HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n", host)
	b.WriteString("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	if origin != "" {
		fmt.Fprintf(&b, "Origin: %s\r\n", origin)
	}
	for k, vs := range extra {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	_, err = conn.Write([]byte(b.String()))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A tunnel or proxy that rewrites the Origin, or a page on any other
// origin, gets neither the probe's CORS answer nor a session: only the
// portal's exact origin is let in.
func TestDirectRefusesARewrittenOrigin(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	for _, origin := range []string{
		"null",
		"http://portal.basaltvault.app",
		"https://portal.basaltvault.app:443",
		"https://PORTAL.basaltvault.app",
		"https://portal.basaltvault.app/",
		"https://portal.basaltvault.app.evil.example",
		"https://evil-portal.basaltvault.app",
		"https://basaltvault.app",
		"https://engine.example.com",
		"http://localhost:8787",
	} {
		resp := f.get(t, "engine.example.com", "/v1/engine", origin)
		require.Equal(t, http.StatusForbidden, resp.status, origin)
		require.Empty(t, resp.header.Get("Access-Control-Allow-Origin"), origin)
		require.Equal(t, http.StatusForbidden, f.upgrade(t, "engine.example.com", origin, nil), origin)
	}
	require.Equal(t, http.StatusForbidden, f.upgrade(t, "engine.example.com", "", nil), "no Origin")
	require.Equal(t, http.StatusSwitchingProtocols, f.upgrade(t, "engine.example.com", links.Portal, nil))
}

// A tunnel that rewrites Host (to the loopback address it forwards to, a
// trailing dot, another port), or a client that claims the address in a
// forwarding header, reaches no route: only the recorded address, as host
// and port, is served.
func TestDirectRefusesARewrittenHost(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	port := f.srv.Listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"engine.example.com", "ENGINE.Example.COM", "engine.example.com:443"} {
		require.Equal(t, http.StatusOK, f.get(t, host, "/v1/engine", "").status, host)
	}
	for _, host := range []string{
		"engine.example.com.",
		"engine.example.com:0443",
		"engine.example.com:8443",
		"engine.example.com:",
		"xengine.example.com",
		"engine.example.com.evil.example",
		"example.com",
		"localhost",
		fmt.Sprintf("localhost:%d", port),
		fmt.Sprintf("127.0.0.1:%d", port),
		"[::1]",
		"portal.basaltvault.app",
	} {
		require.Equal(t, http.StatusBadRequest, f.get(t, host, "/v1/engine", "").status, host)
		require.Equal(t, http.StatusBadRequest, f.upgrade(t, host, links.Portal, nil), host)
	}
	forwarded := http.Header{
		"X-Forwarded-Host": {"engine.example.com"},
		"Forwarded":        {"host=engine.example.com;proto=https"},
		"X-Forwarded-For":  {"203.0.113.7"},
		"X-Real-Ip":        {"203.0.113.7"},
	}
	require.Equal(t, http.StatusBadRequest, f.upgrade(t, "other.example.com", links.Portal, forwarded), "forwarding headers are never read")
}

// Each agent's database decides alone: a link opens only over the address
// its own agent's database records, even when another agent's database
// records the address the request came in on. A revoke in one database
// refuses only that agent's links, honestly, over its own address.
func TestDirectSessionNeedsItsOwnAgentsAddress(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	other := f.addAgent(t, "bot2")
	f.record(t, "https://engine.example.com")
	otherURL := "https://other.example.com"
	_, err := guard.RecordEngine(context.Background(), other.Admin, f.keys.PublicKeySPKI(), &otherURL)
	require.NoError(t, err)
	mine, _ := f.holdLinkOf(t, "bot")
	theirs, theirSecret := f.holdLinkOf(t, "bot2")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := f.dialHost(t, "engine.example.com")
	require.Equal(t, int(channel.ErrLinkRefused), refusedWith(ctx, t, p, p.Handshake(ctx, theirs)), "bot2's link over bot's address")
	p = f.dialHost(t, "other.example.com")
	require.Equal(t, int(channel.ErrLinkRefused), refusedWith(ctx, t, p, p.Handshake(ctx, mine)), "bot's link over bot2's address")

	p = f.dialHost(t, "other.example.com")
	require.NoError(t, p.Handshake(ctx, theirs))
	r, err := p.Do(ctx, http.MethodGet, "/api/v1/approvals/x", pagetest.Headers(theirSecret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status)

	_, err = guard.RevokeEngine(context.Background(), other.Admin, f.keys.EngineID())
	require.NoError(t, err)
	p = f.dialHost(t, "other.example.com")
	require.Equal(t, int(channel.ErrEngineRevoked), refusedWith(ctx, t, p, p.Handshake(ctx, theirs)), "the revoked address still reaches the engine, which says so")
	p = f.dialHost(t, "engine.example.com")
	require.NoError(t, p.Handshake(ctx, mine), "bot's database did not revoke")
}

// A replayed message 1 (the tunnel recorded it) gets a fresh message 2 the
// replayer cannot read, and the recorded frames, replayed into that socket
// or into the first one again, are refused: nothing reaches the pages.
func TestDirectReplayedHandshakeOpensNothing(t *testing.T) {
	t.Parallel()
	pages := &countPages{}
	f := newDirectFixtureWith(t, pages)
	f.record(t, "https://engine.example.com")
	keys, secret, item := f.holdLink(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ini, msg1, err := channel.WriteHello(channel.TransportDirect, keys)
	require.NoError(t, err)
	first := f.dial(t)
	require.NoError(t, first.SendRaw(ctx, msg1))
	msg2, err := first.ReadRaw(ctx)
	require.NoError(t, err)
	session, _, err := ini.ReadWelcome(msg2)
	require.NoError(t, err)
	content, err := json.Marshal(pagetest.Request{
		Type: "REQUEST", ID: 1, Method: http.MethodGet, Path: "/api/v1/approvals/" + item.String(), Headers: pagetest.Headers(secret),
	})
	require.NoError(t, err)
	frame, err := session.Seal(content)
	require.NoError(t, err)
	require.NoError(t, first.SendRaw(ctx, frame))
	answer, err := first.ReadRaw(ctx)
	require.NoError(t, err)
	_, err = session.Open(answer)
	require.NoError(t, err)
	require.Equal(t, int32(1), pages.n.Load())

	replay := f.dial(t)
	require.NoError(t, replay.SendRaw(ctx, msg1))
	again, err := replay.ReadRaw(ctx)
	require.NoError(t, err, "message 1 alone cannot be told from a fresh one")
	require.NotEqual(t, msg2, again, "the engine's ephemeral key is fresh")
	require.NoError(t, replay.SendRaw(ctx, frame))
	require.Equal(t, int(channel.ErrFrameInvalid), int(replay.Closed(ctx)), "the recorded frame does not open in the replayed session")

	require.NoError(t, first.SendRaw(ctx, frame))
	require.Equal(t, int(channel.ErrFrameInvalid), int(first.Closed(ctx)), "a frame replayed in its own session")
	require.Equal(t, int32(1), pages.n.Load(), "no replay reached the pages")
}

// Sockets that never send message 1 hold at most directPending slots; one
// more is answered 503 before the upgrade.
func TestDirectCapsSocketsBeforeTheHandshake(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	for range directPending {
		f.dial(t)
	}
	require.Equal(t, http.StatusServiceUnavailable, f.upgrade(t, "engine.example.com", links.Portal, nil))
}

// A finished handshake frees its slot at once: the cap counts sockets that
// have not finished the handshake, not open sessions.
func TestDirectHandshakeFreesItsPendingSlot(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	for range directPending / 4 {
		keys, _, _ := f.holdLink(t)
		for range 4 {
			require.NoError(t, f.dial(t).Handshake(ctx, keys))
		}
	}
	keys, _, _ := f.holdLink(t)
	require.NoError(t, f.dial(t).Handshake(ctx, keys))
	require.Less(t, time.Since(started), vault.Message1Timeout, "the sessions above opened within one message-1 window")
}

// At most directUpgradesPerMinute upgrades a minute, for the whole
// listener; the next minute starts afresh.
func TestDirectUpgradeRate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	d := &directHandler{now: func() time.Time { return now }}
	for i := range directUpgradesPerMinute {
		require.True(t, d.allowUpgrade(), i)
	}
	require.False(t, d.allowUpgrade())
	now = now.Add(59 * time.Second)
	require.False(t, d.allowUpgrade())
	now = now.Add(time.Second)
	require.True(t, d.allowUpgrade())
}

// rawRequest writes head on a new connection and reads the status.
func (f *directFixture) rawRequest(t *testing.T, head string) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte(head))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The request line and headers may take directHeaderBytes, no more.
func TestDirectRefusesOversizeHeaders(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	head := func(size int) string {
		start := "GET /v1/engine HTTP/1.1\r\nHost: engine.example.com\r\nX-Pad: "
		return start + strings.Repeat("a", size-len(start)-4) + "\r\n\r\n"
	}
	require.Equal(t, http.StatusOK, f.rawRequest(t, head(directHeaderBytes-512)))
	require.Equal(t, http.StatusRequestHeaderFieldsTooLarge, f.rawRequest(t, head(directHeaderBytes+512)))
}

// Slow headers (slowloris) on every connection the listener takes hold the
// cap only until the header timeout: then they are closed and a real probe
// is answered.
func TestDirectSlowHeadersHoldTheCapOnlyUntilTheirTimeout(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	require.Equal(t, http.StatusOK, f.rawRequest(t, "GET /v1/engine HTTP/1.1\r\nHost: engine.example.com\r\nConnection: close\r\n\r\n"), "the record is read")
	slow := make([]net.Conn, 0, directConns)
	for range directConns {
		conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = conn.Write([]byte("GET /v1/engine HTTP/1.1\r\nHost: engine.example.com\r\n"))
		require.NoError(t, err)
		slow = append(slow, conn)
	}
	started := time.Now()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: directHeaderTimeout + 5*time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.srv.URL+"/v1/engine", nil)
	require.NoError(t, err)
	req.Host = "engine.example.com"
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	took := time.Since(started)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Greater(t, took, time.Second, "the cap held the probe while the slow connections were open")
	require.Less(t, took, directHeaderTimeout+3*time.Second, "the slow connections were let go at the header timeout")
	for _, c := range slow {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
		_, err := io.ReadAll(c)
		require.NoError(t, err, "the server closed the slow connection")
	}
}

// A request that went away while it made the engine read its records does
// not fail that read: an attacker that disconnects at once cannot keep a
// just-recorded address out for the next re-read window.
func TestDirectRecordReadOutlivesItsRequest(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	require.True(t, f.records.hostAllowed(gone, "engine.example.com"))
	require.True(t, f.records.hostAllowed(context.Background(), "engine.example.com"))
}
