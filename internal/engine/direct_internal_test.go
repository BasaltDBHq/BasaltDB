package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// directLinks hold one link of agent bot.
type directLinks struct {
	mu sync.Mutex
	m  map[channel.LinkToken]vault.SessionLink
}

func (d *directLinks) Session(t channel.LinkToken) (vault.SessionLink, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.m[t]
	return l, ok
}

type okPages struct{}

func (okPages) Dispatch(_ context.Context, l vault.SessionLink, _ vault.Request) vault.Response {
	return vault.Response{Status: http.StatusOK, ContentType: "text/plain", Body: []byte(l.Item.String())}
}

type directFixture struct {
	srv     *httptest.Server
	db      *guardtest.DB
	keys    *channel.EngineKeys
	links   *directLinks
	records *engineRecords
}

func newDirectFixture(t *testing.T) *directFixture {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, []string{"public.leads"})
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	f := &directFixture{db: d, keys: keys, links: &directLinks{m: map[channel.LinkToken]vault.SessionLink{}}}
	f.records = newEngineRecords(keys.EngineID(), time.Now, log)
	f.records.add("bot", a.Conn)
	sess := vault.NewDirect(vault.DirectOptions{Keys: keys, Log: log, SessionLinks: f.links, Pages: okPages{}})
	ctx, cancel := context.WithCancel(context.Background())
	f.srv = httptest.NewUnstartedServer(nil)
	f.srv.Config = newDirectServer(newDirectHandler(ctx, f.records, keys.PublicKeySPKI(), sess, time.Now))
	f.srv.Start()
	t.Cleanup(func() { cancel(); f.srv.Close() })
	return f
}

func (f *directFixture) record(t *testing.T, url string) {
	t.Helper()
	_, err := guard.RecordEngine(context.Background(), f.db.Admin, f.keys.PublicKeySPKI(), &url)
	require.NoError(t, err)
}

// answer is a response's status, headers and body, read and closed.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (f *directFixture) get(t *testing.T, host, path, origin string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.srv.URL+path, nil)
	require.NoError(t, err)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return answer{status: resp.StatusCode, header: resp.Header, body: body}
}

func (f *directFixture) holdLink(t *testing.T) (channel.LinkKeys, string, uuid.UUID) {
	t.Helper()
	raw := make([]byte, channel.SecretLen)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	item := uuid.Must(uuid.NewV7())
	f.links.mu.Lock()
	f.links.m[keys.Token] = vault.SessionLink{Token: keys.Token, Agent: "bot", Item: item, PSK: keys.PSK, ExpiresAt: time.Now().Add(time.Hour)}
	f.links.mu.Unlock()
	return keys, secret, item
}

func (f *directFixture) dial(t *testing.T, host string) *pagetest.Page {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := pagetest.DialDirect(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http")+"/v1/session", http.Header{"Host": {host}})
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}

// The probe answers only on a recorded address, with CORS for the portal
// only (CONTRACT.md, Direct transport).
func TestDirectProbe(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	require.Equal(t, http.StatusBadRequest, f.get(t, "engine.example.com", "/v1/engine", "").status, "nothing recorded yet")
	f.record(t, "https://engine.example.com")
	// An address just recorded works at once only after the re-read
	// window; the fixture's first read was the refused request above.
	f.records.mu.Lock()
	f.records.readAt = time.Time{}
	f.records.mu.Unlock()

	resp := f.get(t, "engine.example.com", "/v1/engine", "")
	require.Equal(t, http.StatusOK, resp.status)
	require.Empty(t, resp.header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "no-store", resp.header.Get("Cache-Control"))
	var got probe
	require.NoError(t, json.Unmarshal(resp.body, &got))
	require.Equal(t, f.keys.EngineID(), got.EngineID)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(f.keys.PublicKeySPKI()), got.EngineKey)

	resp = f.get(t, "ENGINE.example.com:443", "/v1/engine", links.Portal)
	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, links.Portal, resp.header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, "Origin", resp.header.Get("Vary"))

	require.Equal(t, http.StatusForbidden, f.get(t, "engine.example.com", "/v1/engine", "https://evil.example").status)
	for _, host := range []string{"localhost", "127.0.0.1", "other.example.com", "engine.example.com:8443"} {
		require.Equal(t, http.StatusBadRequest, f.get(t, host, "/v1/engine", "").status, host)
	}
	for _, path := range []string{"/healthz", "/approvals/x", "/api/v1/approvals/x", "/"} {
		resp := f.get(t, "engine.example.com", path, "")
		require.Equal(t, http.StatusNotFound, resp.status, path)
		require.Empty(t, resp.body, path)
	}
	require.Equal(t, http.StatusForbidden, f.get(t, "engine.example.com", "/v1/session", "").status, "no Origin")
	require.Equal(t, http.StatusBadRequest, f.get(t, "engine.example.com", "/v1/session", links.Portal).status, "not an upgrade")
}

// A session over the recorded address is served; revoked in the agent's
// database it closes with ENGINE_REVOKED, after the tag check.
func TestDirectSessionFollowsTheRecord(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	f.record(t, "https://engine.example.com")
	keys, secret, item := f.holdLink(t)

	p := f.dial(t, "engine.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Handshake(ctx, keys))
	require.Equal(t, f.keys.EngineID(), channel.EngineIDOf(p.Welcome.EngineKey))
	r, err := p.Do(ctx, http.MethodGet, "/api/v1/approvals/"+item.String(), pagetest.Headers(secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, item.String(), r.Body)

	// Another address recorded for the agent: the old one still reaches the
	// listener (its Host was read) but the session is refused.
	f.record(t, "https://moved.example.com")
	p = f.dial(t, "engine.example.com")
	require.Equal(t, int(channel.ErrLinkRefused), refusedWith(ctx, t, p, p.Handshake(ctx, keys)))

	_, err = guard.RevokeEngine(context.Background(), f.db.Admin, f.keys.EngineID())
	require.NoError(t, err)
	p = f.dial(t, "engine.example.com")
	require.Equal(t, int(channel.ErrEngineRevoked), refusedWith(ctx, t, p, p.Handshake(ctx, keys)))
}

// refusedWith is the close code a failed handshake got.
func refusedWith(ctx context.Context, t *testing.T, p *pagetest.Page, err error) int {
	t.Helper()
	require.Error(t, err)
	if c := websocket.CloseStatus(err); c != -1 {
		return int(c)
	}
	return int(p.Closed(ctx))
}

// An idle kept-alive connection is closed, so idle clients cannot hold
// the listener's connection cap.
func TestDirectClosesIdleConnections(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET /v1/engine HTTP/1.1\r\nHost: other.example.com\r\n\r\n"))
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(directIdleTimeout+3*time.Second)))
	_, err = r.ReadByte()
	require.ErrorIs(t, err, io.EOF, "the server closed the idle connection")
}

// countingQuerier fails every read, slowly, and counts them.
type countingQuerier struct {
	guard.Querier
	n atomic.Int32
}

func (q *countingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.n.Add(1)
	time.Sleep(50 * time.Millisecond)
	return nil, errors.New("database down")
}

// Many requests with an unknown Host at once read the records once, and an
// agent whose read fails keeps the address it had.
func TestDirectHostMissesReadOnce(t *testing.T) {
	t.Parallel()
	q := &countingQuerier{}
	r := newEngineRecords("AAAAAAAAAAAAAAAAAAAAAA", time.Now, slog.New(slog.DiscardHandler))
	r.add("bot", q)
	r.byAgent["bot"], r.hosts["engine.example.com"] = "engine.example.com", true
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { r.hostAllowed(context.Background(), "nope.example.com") })
	}
	wg.Wait()
	require.Equal(t, int32(1), q.n.Load())
	require.True(t, r.hostAllowed(context.Background(), "engine.example.com"), "a failed read keeps the agent's address")
}

// A request that announces a body that never comes is refused at once and
// its connection closed: it cannot hold a slot of the connection cap.
func TestDirectRefusesARequestBody(t *testing.T) {
	t.Parallel()
	f := newDirectFixture(t)
	for _, head := range []string{
		"POST /v1/engine HTTP/1.1\r\nHost: anything\r\nContent-Length: 1000\r\n\r\n",
		"GET /v1/engine HTTP/1.1\r\nHost: anything\r\nTransfer-Encoding: chunked\r\n\r\n",
	} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		_, err = conn.Write([]byte(head))
		require.NoError(t, err)
		r := bufio.NewReader(conn)
		resp, err := http.ReadResponse(r, nil)
		require.NoError(t, err, head)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_, err = r.ReadByte()
		require.ErrorIs(t, err, io.EOF, "the connection is closed")
		_ = conn.Close()
	}
}
