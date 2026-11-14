package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Message1Timeout is how long a direct socket may wait for handshake
// message 1 after the upgrade (CONTRACT.md, Direct transport, Limits).
const Message1Timeout = 3 * time.Second

// DirectOptions configure the direct transport's sessions: the page's own
// socket to the engine through the person's tunnel (CONTRACT.md, Direct
// transport). Keys is required.
type DirectOptions struct {
	Keys Keys
	Log  *slog.Logger
	Now  func() time.Time
	// SessionLinks resolve message 1's token to its live link, and Pages
	// answer the session's requests: with either nil every session is
	// refused at message 1.
	SessionLinks SessionLinks
	Pages        Dispatcher
	// Message1Timeout, IdleTimeout and SessionLifetime default to the
	// contract's values when zero. Tests shorten them.
	Message1Timeout time.Duration
	IdleTimeout     time.Duration
	SessionLifetime time.Duration
}

// Direct serves link sessions on page sockets that reach the engine
// directly. One session per socket. Its sessions share one table, so the
// per-link and per-engine limits hold across every direct socket.
type Direct struct {
	c        *Client
	sessions *sessions
	timeout  time.Duration

	mu    sync.Mutex
	conns map[sid]*conn
}

// NewDirect returns the direct transport's session server. It panics
// without Keys.
func NewDirect(o DirectOptions) *Direct {
	if o.Keys == nil {
		panic("vault: NewDirect needs the engine's keys")
	}
	opts := Options{
		Keys: o.Keys, Log: o.Log, Now: o.Now, SessionLinks: o.SessionLinks, Pages: o.Pages,
		IdleTimeout: o.IdleTimeout, SessionLifetime: o.SessionLifetime, HandshakeTimeout: o.Message1Timeout,
	}
	setDefault(&opts.HandshakeTimeout, Message1Timeout)
	opts.defaults()
	return &Direct{
		c: &Client{opts: opts}, sessions: newSessions(opts.HandshakeTimeout, opts.Now),
		timeout: opts.HandshakeTimeout, conns: map[sid]*conn{},
	}
}

// directCarrier is the page's own socket: the engine's messages as they
// are, and the session's end as the socket's close code.
type directCarrier struct{ ws *websocket.Conn }

func (d directCarrier) send(ctx context.Context, _ sid, payload []byte) error {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return d.ws.Write(wctx, websocket.MessageBinary, payload)
}

func (d directCarrier) closeSession(_ context.Context, _ sid, code channel.CloseError) error {
	closeWith(d.ws, code)
	return nil
}

// Serve runs one page socket's session until it ends: message 1 within
// the timeout, then frames. The socket ends with the session; a socket
// that ends first ends the session. admit decides, after message 1's tag
// and point, whether the link's agent is served over this socket's address:
// ENGINE_REVOKED, LINK_REFUSED or TIMEOUT to refuse, 0 to serve; nil serves
// every link.
func (d *Direct) Serve(ctx context.Context, ws *websocket.Conn, admit func(context.Context, SessionLink) channel.CloseError) {
	ws.SetReadLimit(channel.FrameMax + 1)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var id sid
	if _, err := rand.Read(id[:]); err != nil {
		closeWith(ws, channel.ErrProtocol)
		return
	}
	cn := &conn{
		c: d.c, ws: ws, sessions: d.sessions, ctx: sctx, done: make(chan struct{}),
		out: directCarrier{ws: ws}, transport: channel.TransportDirect, admit: admit,
	}
	d.track(id, cn)
	defer func() {
		d.untrack(id)
		if ss := d.sessions.take(id); ss != nil {
			ss.stop()
		}
		cn.workers.Wait()
		close(cn.done)
		_ = ws.CloseNow()
	}()
	stop := context.AfterFunc(ctx, func() { closeWith(ws, channel.ErrEngineShutdown) })
	defer stop()

	msg, code := d.readHello(sctx, ws)
	if code != 0 {
		closeWith(ws, code)
		return
	}
	var token channel.LinkToken
	if len(msg) == channel.Message1Len {
		copy(token[:], msg[2:2+channel.LinkTokenLen])
	}
	if code, _ := d.sessions.add(id, token); code != 0 {
		closeWith(ws, code)
		return
	}
	_, ss := d.sessions.lookup(id)
	if err := cn.handshake(sctx, ss, msg); err != nil {
		return
	}
	for {
		ph, ss := d.sessions.lookup(id)
		if ph != phaseOpen {
			return
		}
		payload, code := readDirect(sctx, ws, channel.FrameMax)
		if code != 0 {
			_ = cn.end(sctx, id, code)
			return
		}
		if payload == nil {
			return
		}
		if err := cn.frame(sctx, ss, payload); err != nil {
			return
		}
	}
}

// readHello reads message 1 within the timeout; past it the socket is
// closed with TIMEOUT (a read's own deadline would drop the socket with no
// code). A message over its size is refused as the handshake's own check
// would: PROTOCOL.
func (d *Direct) readHello(ctx context.Context, ws *websocket.Conn) ([]byte, channel.CloseError) {
	late := time.AfterFunc(d.timeout, func() { closeWith(ws, channel.ErrTimeout) })
	defer late.Stop()
	msg, code := readDirect(ctx, ws, channel.Message1Len)
	switch {
	case code == channel.ErrTooLarge:
		return nil, channel.ErrProtocol
	case code != 0:
		return nil, code
	case msg == nil:
		return nil, channel.ErrProtocol
	}
	return msg, 0
}

// readDirect reads one binary message of at most limit bytes: TOO_LARGE
// over it, PROTOCOL for a text message, and nil with no code when the
// socket ended.
func readDirect(ctx context.Context, ws *websocket.Conn, limit int) ([]byte, channel.CloseError) {
	typ, r, err := ws.Reader(ctx)
	if err != nil {
		return nil, 0
	}
	if typ != websocket.MessageBinary {
		return nil, channel.ErrProtocol
	}
	data, over, err := readBounded(r, limit)
	switch {
	case err != nil:
		var ce websocket.CloseError
		if errors.As(err, &ce) && ce.Code == websocket.StatusMessageTooBig {
			return nil, channel.ErrTooLarge
		}
		return nil, 0
	case over:
		return nil, channel.ErrTooLarge
	}
	return data, 0
}

func (d *Direct) track(id sid, cn *conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conns[id] = cn
}

func (d *Direct) untrack(id sid) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.conns, id)
}

// EndLink ends every direct session of token with LINK_REFUSED: its link
// was revoked or expired.
func (d *Direct) EndLink(token channel.LinkToken) {
	for _, id := range d.sessions.ofToken(token) {
		d.mu.Lock()
		cn := d.conns[id]
		d.mu.Unlock()
		if cn != nil {
			cn.endAsync(id, channel.ErrLinkRefused)
		}
	}
}

// EndAll ends every direct session with code: ENGINE_REVOKED when the
// engine's key is revoked, ENGINE_SHUTDOWN when it stops.
func (d *Direct) EndAll(code channel.CloseError) {
	d.mu.Lock()
	all := make(map[sid]*conn, len(d.conns))
	for id, cn := range d.conns {
		all[id] = cn
	}
	d.mu.Unlock()
	for id, cn := range all {
		cn.endAsync(id, code)
	}
}
