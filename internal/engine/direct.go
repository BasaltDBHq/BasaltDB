package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/websec"
)

// The direct listener's limits (CONTRACT.md, Direct transport). Clients
// behind a tunnel cannot be told apart, so they are for the whole listener.
const (
	// directPending is the most sockets at a time still in their handshake.
	directPending = 16
	// directUpgradesPerMinute is the most upgrades the listener takes a
	// minute.
	directUpgradesPerMinute = 600
	// directHeaderTimeout and directHeaderBytes bound a request's headers.
	directHeaderTimeout = 5 * time.Second
	directHeaderBytes   = 8 << 10
	// headerSlop is what net/http reads past Server.MaxHeaderBytes before
	// it answers 431, so the server is given directHeaderBytes less it.
	headerSlop = 4 << 10
	// directConns is the most connections open on the listener.
	directConns = 64
	// recordReadTimeout bounds one read of the engine's record.
	recordReadTimeout = 5 * time.Second
	// recordRereadAfter is how soon a Host not among the addresses read
	// makes the engine read them again.
	recordRereadAfter = 10 * time.Second
	// directIdleTimeout closes a kept-alive connection with no next
	// request, so idle connections cannot hold the connection cap.
	directIdleTimeout = 5 * time.Second
	// directReadTimeout and directWriteTimeout bound a whole request's read
	// and a response's write. They are the backstop where a response
	// writer cannot set its own deadline (refuse), and keep a local
	// process that pipelines probes and never reads from holding a
	// connection slot. A WebSocket upgrade hijacks the connection, which
	// clears them.
	directReadTimeout  = 10 * time.Second
	directWriteTimeout = 10 * time.Second
	// directShutdownTimeout bounds the listener's shutdown.
	directShutdownTimeout = 5 * time.Second
	httpsPort             = "443"
)

// engineRecords are this engine's record in each agent's database
// (basalt_meta version 33): the addresses its direct listener answers on
// and whether an agent's database revoked it.
type engineRecords struct {
	engineID string
	now      func() time.Time
	log      *slog.Logger

	mu     sync.Mutex
	agents map[string]guard.Querier
	// byAgent is each agent's recorded address host[:port] (no :443),
	// revoked or not, from its last good read; hosts is their set.
	byAgent map[string]string
	hosts   map[string]bool
	// readAt is when the last read started; reading is set while one runs,
	// so concurrent misses wait for the next window instead of reading too.
	readAt  time.Time
	reading bool
}

func newEngineRecords(engineID string, now func() time.Time, log *slog.Logger) *engineRecords {
	return &engineRecords{engineID: engineID, now: now, log: log, agents: map[string]guard.Querier{}, byAgent: map[string]string{}, hosts: map[string]bool{}}
}

// add takes an agent's database connection.
func (r *engineRecords) add(agent string, q guard.Querier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[agent] = q
}

// read is the engine's row in agent's database, nil when not recorded.
func (r *engineRecords) read(ctx context.Context, agent string) (*guard.RecordedEngine, error) {
	r.mu.Lock()
	q, ok := r.agents[agent]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no agent %q", agent)
	}
	rctx, cancel := context.WithTimeout(ctx, recordReadTimeout)
	defer cancel()
	return guard.EngineRecord(rctx, q, r.engineID)
}

// refresh reads every agent's record and keeps the addresses. An agent
// whose read fails keeps the address of its last good read.
func (r *engineRecords) refresh(ctx context.Context) {
	r.mu.Lock()
	names := make([]string, 0, len(r.agents))
	for n := range r.agents {
		names = append(names, n)
	}
	r.reading, r.readAt = true, r.now()
	r.mu.Unlock()
	read := map[string]string{}
	failed := map[string]bool{}
	for _, n := range names {
		e, err := r.read(ctx, n)
		switch {
		case err != nil:
			r.log.Debug("direct: read the engine's record", "agent", n, "err", err)
			failed[n] = true
		case e != nil && e.URL != nil:
			read[n] = strings.TrimPrefix(*e.URL, "https://")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range names {
		if !failed[n] {
			r.byAgent[n] = read[n]
		}
	}
	hosts := map[string]bool{}
	for _, h := range r.byAgent {
		if h != "" {
			hosts[h] = true
		}
	}
	r.hosts, r.reading = hosts, false
}

// hostAllowed is whether host (a request's Host) is an address recorded
// for this engine, revoked or not. A host not among the last read makes the
// engine read again, at most once every recordRereadAfter whatever the
// number of requests: a miss while a read runs or within the window
// answers from what was last read.
func (r *engineRecords) hostAllowed(ctx context.Context, host string) bool {
	host = normalHost(host)
	r.mu.Lock()
	ok := r.hosts[host]
	stale := !r.reading && r.now().Sub(r.readAt) >= recordRereadAfter
	if !ok && stale {
		r.reading, r.readAt = true, r.now()
	}
	r.mu.Unlock()
	if ok || !stale {
		return ok
	}
	// The read is not the request's: a client that goes away at once
	// would otherwise fail it and keep a just-recorded address out until
	// the next window.
	r.refresh(context.WithoutCancel(ctx))
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hosts[host]
}

// normalHost is a Host header as an engine address's host[:port]:
// lowercase, with :443 dropped.
func normalHost(host string) string {
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil && p == httpsPort {
		return h
	}
	return host
}

// admit is the session check for a socket that came on host: the link's
// agent's database must record this engine at host and not have revoked
// it (CONTRACT.md, Direct transport, The engine on message 1).
func (r *engineRecords) admit(host string) func(context.Context, vault.SessionLink) channel.CloseError {
	host = normalHost(host)
	return func(ctx context.Context, l vault.SessionLink) channel.CloseError {
		e, err := r.read(ctx, l.Agent)
		switch {
		case err != nil:
			r.log.Warn("direct: could not read the engine's record; session refused", "agent", l.Agent, "err", err)
			return channel.ErrTimeout
		case e == nil:
			return channel.ErrLinkRefused
		case e.RevokedAt != nil:
			return channel.ErrEngineRevoked
		case e.URL == nil || strings.TrimPrefix(*e.URL, "https://") != host:
			return channel.ErrLinkRefused
		}
		return 0
	}
}

// directHandler serves the direct listener's two routes.
type directHandler struct {
	records *engineRecords
	key     []byte
	sess    *vault.Direct
	ctx     context.Context
	now     func() time.Time
	pending chan struct{}

	mu          sync.Mutex
	windowStart time.Time
	upgrades    int
}

func newDirectHandler(ctx context.Context, records *engineRecords, key []byte, sess *vault.Direct, now func() time.Time) http.Handler {
	d := &directHandler{records: records, key: key, sess: sess, ctx: ctx, now: now, pending: make(chan struct{}, directPending)}
	return websec.Headers()(d)
}

// probe is GET /v1/engine's answer (api/mcp/vault/direct-engine.schema.json).
type probe struct {
	EngineKey string `json:"engineKey"`
	EngineID  string `json:"engineId"`
}

func (d *directHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Both routes are a GET with no body. A body is refused before anything
	// else, with the connection closed: net/http would otherwise wait,
	// without a deadline, to drain a body that never comes, holding a slot
	// of the connection cap.
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		refuse(w, "no request body here", http.StatusBadRequest)
		return
	}
	if !d.records.hostAllowed(r.Context(), r.Host) {
		refuse(w, "host not allowed", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/engine":
		d.probe(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/session":
		d.session(w, r)
	default:
		stopReading(w)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNotFound)
	}
}

// stopReading sets the request's read deadline to now, so net/http does
// not wait to drain a body the client never sends. A response writer that
// cannot set it (a wrapper without Unwrap) leaves the server's
// directReadTimeout to bound the read: the refusal is still answered and
// the connection closed, only later.
func stopReading(w http.ResponseWriter) {
	if err := http.NewResponseController(w).SetReadDeadline(time.Now()); err != nil {
		slog.Debug("direct: stop reading a refused request", "err", err)
	}
}

// refuse answers a refusal and closes the connection after it. The read
// deadline is set to now first, so net/http does not wait to drain a
// request body the client never sends.
func refuse(w http.ResponseWriter, msg string, status int) {
	stopReading(w)
	w.Header().Set("Connection", "close")
	http.Error(w, msg, status)
}

func (d *directHandler) probe(w http.ResponseWriter, r *http.Request) {
	switch origin := r.Header.Get("Origin"); origin {
	case "":
	case links.Portal:
		w.Header().Set("Access-Control-Allow-Origin", links.Portal)
		w.Header().Set("Vary", "Origin")
	default:
		refuse(w, "origin not allowed", http.StatusForbidden)
		return
	}
	body, err := json.Marshal(probe{EngineKey: base64.RawURLEncoding.EncodeToString(d.key), EngineID: channel.EngineIDOf(d.key)})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (d *directHandler) session(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != links.Portal {
		refuse(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		refuse(w, "a WebSocket upgrade only", http.StatusBadRequest)
		return
	}
	if !d.allowUpgrade() {
		refuse(w, "too many sessions; try later", http.StatusServiceUnavailable)
		return
	}
	select {
	case d.pending <- struct{}{}:
	default:
		refuse(w, "too many sessions; try later", http.StatusServiceUnavailable)
		return
	}
	var once sync.Once
	release := func() { once.Do(func() { <-d.pending }) }
	defer release()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{strings.TrimPrefix(links.Portal, "https://")}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	// A socket holds its pending slot only while message 1 may still come.
	t := time.AfterFunc(vault.Message1Timeout, release)
	defer t.Stop()
	// The socket ends with the request or with the engine.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(d.ctx, cancel) //nolint:contextcheck // the engine stopping ends the socket too, not only the request
	defer stop()
	// The handshake ends with the record's check (message 2 follows at
	// once), so the slot is free for the next socket from then on.
	admit := d.records.admit(r.Host)
	d.sess.Serve(ctx, ws, func(actx context.Context, l vault.SessionLink) channel.CloseError {
		defer release()
		return admit(actx, l)
	})
}

// allowUpgrade counts an upgrade against directUpgradesPerMinute.
func (d *directHandler) allowUpgrade() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if now.Sub(d.windowStart) >= time.Minute {
		d.windowStart, d.upgrades = now, 0
	}
	if d.upgrades >= directUpgradesPerMinute {
		return false
	}
	d.upgrades++
	return true
}

// directSite is the bound direct listener.
type directSite struct {
	ln net.Listener
}

// listenDirect binds the direct listener. An address it cannot bind stops
// the engine, as for the pages.
func listenDirect(addr string) (*directSite, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("directAddr %s: %w (find what holds it with `lsof -nP -iTCP -sTCP:LISTEN`)", addr, err)
	}
	return &directSite{ln: &limitListener{Listener: ln, sem: make(chan struct{}, directConns)}}, nil
}

// newDirectServer is the listener's HTTP server: headers within
// directHeaderTimeout, an idle kept-alive connection closed after
// directIdleTimeout.
func newDirectServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h, ReadHeaderTimeout: directHeaderTimeout, ReadTimeout: directReadTimeout, WriteTimeout: directWriteTimeout,
		IdleTimeout: directIdleTimeout, MaxHeaderBytes: directHeaderBytes - headerSlop,
	}
}

// serve answers on the listener until ctx ends, then ends the direct
// sessions (ENGINE_SHUTDOWN) and shuts the server down within
// directShutdownTimeout.
func (s *directSite) serve(ctx context.Context, h http.Handler, sess *vault.Direct, log *slog.Logger) {
	hs := newDirectServer(h)
	go func() {
		<-ctx.Done()
		sess.EndAll(channel.ErrEngineShutdown)
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directShutdownTimeout)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if err := hs.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("direct listener stopped", "err", err)
	}
}

// limitListener holds at most cap(sem) connections open: Accept waits for
// one to close.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
