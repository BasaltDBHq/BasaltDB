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
	// directConns is the most connections open on the listener.
	directConns = 64
	// recordReadTimeout bounds one read of the engine's record.
	recordReadTimeout = 5 * time.Second
	// recordRereadAfter is how soon a Host not among the addresses read
	// makes the engine read them again.
	recordRereadAfter = 10 * time.Second
	httpsPort         = "443"
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
	// hosts are the recorded addresses' host[:port] (no :443), revoked or
	// not, from the last read; readAt is when.
	hosts  map[string]bool
	readAt time.Time
}

func newEngineRecords(engineID string, now func() time.Time, log *slog.Logger) *engineRecords {
	return &engineRecords{engineID: engineID, now: now, log: log, agents: map[string]guard.Querier{}, hosts: map[string]bool{}}
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
// whose read fails keeps none until the next read.
func (r *engineRecords) refresh(ctx context.Context) {
	r.mu.Lock()
	names := make([]string, 0, len(r.agents))
	for n := range r.agents {
		names = append(names, n)
	}
	r.mu.Unlock()
	hosts := map[string]bool{}
	for _, n := range names {
		e, err := r.read(ctx, n)
		if err != nil {
			r.log.Debug("direct: read the engine's record", "agent", n, "err", err)
			continue
		}
		if e != nil && e.URL != nil {
			hosts[strings.TrimPrefix(*e.URL, "https://")] = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts, r.readAt = hosts, r.now()
}

// hostAllowed is whether host (a request's Host) is an address recorded
// for this engine, revoked or not. A host not among the last read makes it
// read again, at most every recordRereadAfter.
func (r *engineRecords) hostAllowed(ctx context.Context, host string) bool {
	host = normalHost(host)
	r.mu.Lock()
	ok, stale := r.hosts[host], r.now().Sub(r.readAt) >= recordRereadAfter
	r.mu.Unlock()
	if ok || !stale {
		return ok
	}
	r.refresh(ctx)
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
	if !d.records.hostAllowed(r.Context(), r.Host) {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/engine":
		d.probe(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/session":
		d.session(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *directHandler) probe(w http.ResponseWriter, r *http.Request) {
	switch origin := r.Header.Get("Origin"); origin {
	case "":
	case links.Portal:
		w.Header().Set("Access-Control-Allow-Origin", links.Portal)
		w.Header().Set("Vary", "Origin")
	default:
		http.Error(w, "origin not allowed", http.StatusForbidden)
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
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "a WebSocket upgrade only", http.StatusBadRequest)
		return
	}
	if !d.allowUpgrade() {
		http.Error(w, "too many sessions; try later", http.StatusServiceUnavailable)
		return
	}
	select {
	case d.pending <- struct{}{}:
	default:
		http.Error(w, "too many sessions; try later", http.StatusServiceUnavailable)
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
	d.sess.Serve(ctx, ws, d.records.admit(r.Host))
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
	hs *http.Server
}

// listenDirect binds the direct listener. An address it cannot bind stops
// the engine, as for the pages.
func listenDirect(addr string, h http.Handler) (*directSite, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("directAddr %s: %w (find what holds it with `lsof -nP -iTCP -sTCP:LISTEN`)", addr, err)
	}
	ln = &limitListener{Listener: ln, sem: make(chan struct{}, directConns)}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: directHeaderTimeout, MaxHeaderBytes: directHeaderBytes}
	return &directSite{ln: ln, hs: hs}, nil
}

func (s *directSite) serve(ctx context.Context, log *slog.Logger) {
	go func() {
		<-ctx.Done()
		_ = s.hs.Shutdown(context.WithoutCancel(ctx))
	}()
	if err := s.hs.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
