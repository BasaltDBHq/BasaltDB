package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// loopbackHosts are the only hosts a ws:// (plaintext) Vault URL may name.
var loopbackHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// challengeLen is the size of a decoded CHALLENGE.
const challengeLen = 32

// writeTimeout bounds one write to the socket.
const writeTimeout = 5 * time.Second

// target is where the engine dials and the host it signs into AUTH.
type target struct {
	url  string
	host string
}

// newTarget builds the engine socket URL from a ws:// or wss:// base. The
// host signed into AUTH is the engine's own (host, or host:port when the
// URL names a port), never one the Vault names.
func newTarget(base, engineID string) (target, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return target{}, fmt.Errorf("vault: %q is not a ws:// or wss:// base URL", base)
	}
	// Plaintext only to this machine: config refuses any other ws:// URL
	// already, and this keeps the client from dialing one either way.
	if u.Scheme == "ws" && !loopbackHosts[strings.ToLower(u.Hostname())] {
		return target{}, fmt.Errorf("vault: %q: ws:// is for a loopback Vault only (127.0.0.1, [::1] or localhost); use wss://", base)
	}
	return target{url: u.Scheme + "://" + u.Host + "/v1/engines/" + engineID, host: u.Host}, nil
}

// closedError is a socket the engine closed with a registry code; the code
// says why.
type closedError struct{ code channel.CloseError }

func (e closedError) Error() string { return "closed the socket with " + e.code.String() }

// closeCode is the code and name of a socket the Vault closed, for the log.
func closeCode(err error) string {
	code := websocket.CloseStatus(err)
	if code < 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", code, channel.CloseError(code).String())
}

// conn is one socket: dialed, authenticated, then read until it ends.
type conn struct {
	c        *Client
	ws       *websocket.Conn
	sessions sessions
}

// connect dials, authenticates and serves one socket until it ends. ready
// reports whether the Vault sent READY on it.
func (c *Client) connect(ctx context.Context) (bool, error) {
	ws, err := c.dialAndAuth(ctx)
	if err != nil {
		return false, err
	}
	cn := &conn{c: c, ws: ws, sessions: newSessions(c.opts.HandshakeTimeout, c.opts.Now)}
	c.setConnected(true)
	c.opts.Log.Info("vault socket ready", "engineId", c.opts.Keys.EngineID())
	return true, cn.serve(ctx)
}

// dialAndAuth opens the socket and runs CHALLENGE, AUTH and READY within
// AuthTimeout. Until READY the transport reads at most a control message.
func (c *Client) dialAndAuth(ctx context.Context) (*websocket.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, c.opts.AuthTimeout)
	defer cancel()
	header := http.Header{}
	header.Set(EngineKeyHeader, b64(c.opts.Keys.PublicKeySPKI()))
	ws, resp, err := websocket.Dial(actx, c.target.url, &websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: noRedirects,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("vault: dial: %w", err)
	}
	ws.SetReadLimit(maxControl + 1)
	if err := c.authenticate(actx, ws); err != nil {
		var ec closedError
		if errors.As(err, &ec) {
			closeWith(ws, ec.code)
		}
		_ = ws.CloseNow()
		return nil, err
	}
	return ws, nil
}

// noRedirects follows no redirect: the engine talks to the URL it was
// given, never one the Vault names.
var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

// authenticate answers CHALLENGE and waits for READY.
func (c *Client) authenticate(ctx context.Context, ws *websocket.Conn) error {
	ch, err := readControlBefore(ctx, ws, typeChallenge)
	if err != nil {
		return err
	}
	sig, err := c.opts.Keys.Sign(channel.ContextVaultAuth, []byte(ch.challenge+"\n"+c.target.host))
	if err != nil {
		return fmt.Errorf("vault: sign the challenge: %w", err)
	}
	if err := writeJSON(ctx, ws, authMsg{Type: typeAuth, Version: authVersion, Sig: b64(sig)}); err != nil {
		return err
	}
	_, err = readControlBefore(ctx, ws, typeReady)
	return err
}

// readControlBefore reads one message before READY: it must be a control
// message of type want, at most 4 KiB.
func readControlBefore(ctx context.Context, ws *websocket.Conn, want string) (control, error) {
	typ, r, err := ws.Reader(ctx)
	if err != nil {
		return control{}, readErr(err)
	}
	if typ != websocket.MessageText {
		return control{}, closedError{channel.ErrProtocol}
	}
	data, over, err := readBounded(r, maxControl)
	switch {
	case err != nil:
		return control{}, readErr(err)
	case over:
		return control{}, closedError{channel.ErrTooLarge}
	}
	m, err := parseControl(data)
	if err != nil || m.typ != want {
		return control{}, closedError{channel.ErrProtocol}
	}
	return m, nil
}

// readErr names a socket that ended: by the Vault's close code when it sent one.
func readErr(err error) error {
	if code := closeCode(err); code != "" {
		return fmt.Errorf("vault: the Vault closed the socket with %s: %w", code, err)
	}
	return fmt.Errorf("vault: read: %w", err)
}

// serve reads the socket until it ends, pinging it meanwhile. When ctx
// ends the engine closes the socket with ENGINE_SHUTDOWN.
func (cn *conn) serve(ctx context.Context) error {
	cn.ws.SetReadLimit(maxRoute + 1)
	// The socket's own context: reads and pings use it, so the engine closes
	// the socket itself (with a code) when ctx ends, rather than the
	// transport dropping it.
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		closeWith(cn.ws, channel.ErrEngineShutdown)
	})
	defer func() {
		if !stop() {
			<-closed // the shutdown close ran: return once it is done
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() { cn.ping(sctx) })

	for {
		err := cn.readOne(sctx)
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return err // stopping: the socket closes with ENGINE_SHUTDOWN
		}
		var ec closedError
		if errors.As(err, &ec) {
			closeWith(cn.ws, ec.code)
		}
		_ = cn.ws.CloseNow()
		return err
	}
}

// ping pings every PingInterval and closes the socket when a pong does not
// come within PongTimeout; the read loop then ends and the engine redials.
func (cn *conn) ping(ctx context.Context) {
	o := cn.c.opts
	for sleep(ctx, o.PingInterval) {
		pctx, cancel := context.WithTimeout(ctx, o.PongTimeout)
		err := cn.ws.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				o.Log.Warn("vault socket: no pong; dialing again", "err", err)
			}
			_ = cn.ws.CloseNow()
			return
		}
	}
}

// readOne reads and handles one message after READY.
func (cn *conn) readOne(ctx context.Context) error {
	typ, r, err := cn.ws.Reader(ctx)
	if err != nil {
		return readErr(err)
	}
	if typ == websocket.MessageBinary {
		return cn.route(ctx, r)
	}
	data, over, err := readBounded(r, maxControl)
	switch {
	case err != nil:
		return readErr(err)
	case over:
		return closedError{channel.ErrTooLarge}
	}
	m, err := parseControl(data)
	if err != nil {
		return closedError{channel.ErrProtocol}
	}
	return cn.control(ctx, m)
}

// control handles a control message after READY.
func (cn *conn) control(ctx context.Context, m control) error {
	switch m.typ {
	case typeSessionOpen:
		return cn.sessionOpen(ctx, m.sessionOpen)
	case typeSessionClose:
		cn.sessions.remove(m.sessionClose.sid)
		return nil
	case typeOK, typeError:
		// The engine has no request waiting for an answer until it
		// registers links (VC1-6), so any answer is a forged one: ignored.
		cn.c.opts.Log.Debug("vault socket: an answer to no request", "type", m.typ)
		return nil
	default:
		// A second CHALLENGE or READY is out of place.
		return closedError{channel.ErrProtocol}
	}
}

// sessionOpen starts waiting for a session's message 1, within the limits.
func (cn *conn) sessionOpen(ctx context.Context, m *sessionOpen) error {
	for _, id := range cn.sessions.expired() {
		if err := cn.closeSession(ctx, id, channel.ErrTimeout); err != nil {
			return err
		}
	}
	code := cn.sessions.add(m.sid, m.token)
	if code == 0 {
		return nil
	}
	return cn.closeSession(ctx, m.sid, code)
}

// route reads a ROUTE message: the header, then the payload up to its
// session's phase limit, so nothing larger is held in memory.
func (cn *conn) route(ctx context.Context, r io.Reader) error {
	id, err := readRouteHeader(r)
	if err != nil {
		return err
	}
	limit, token, awaitingHello := cn.sessions.limit(id)
	payload, over, err := readBounded(r, limit)
	if err != nil {
		return readErr(err)
	}
	if over {
		return cn.oversize(ctx, r, id, limit, awaitingHello)
	}
	if !awaitingHello {
		// A session the engine does not hold (one it closed, whose bytes
		// were still on their way): dropped.
		return nil
	}
	// A message 1 past the handshake timeout is not read: the session ends
	// with TIMEOUT, as it would have on a timer.
	late := cn.sessions.late(id)
	cn.sessions.remove(id)
	if late {
		return cn.closeSession(ctx, id, channel.ErrTimeout)
	}
	return cn.closeSession(ctx, id, hello(payload, token))
}

// oversize handles a ROUTE payload over its session's limit: the rest is
// drained without being kept, and a message over the ROUTE limit closes the
// socket with TOO_LARGE. A message 1 that is not 99 bytes closes its session
// with PROTOCOL.
func (cn *conn) oversize(ctx context.Context, r io.Reader, id sid, limit int, awaitingHello bool) error {
	read := int64(routeHeaderLen + limit + 1)
	n, err := io.CopyN(io.Discard, r, maxRoute+1-read)
	switch {
	case read+n > maxRoute:
		return closedError{channel.ErrTooLarge}
	case err != nil && !errors.Is(err, io.EOF):
		return readErr(err)
	case !awaitingHello:
		return nil
	}
	cn.sessions.remove(id)
	return cn.closeSession(ctx, id, channel.ErrProtocol)
}

// noLinks is the engine's link lookup until VC1-6 and VC1-7: it holds no
// link the Vault can route, so every token is one it does not hold.
func noLinks(channel.LinkToken) (channel.PSK, bool) { return channel.PSK{}, false }

// hello checks a session's message 1 against SESSION_OPEN's token as the
// contract orders it and returns the code that closes the session. With no
// link held, a well-formed one is refused as a dead token is: LINK_REFUSED.
func hello(msg []byte, token channel.LinkToken) channel.CloseError {
	_, err := channel.ReadHello(msg, channel.HelloCheck{Transport: channel.TransportRelay, SessionToken: &token, Lookup: noLinks})
	var ce channel.CloseError
	if errors.As(err, &ce) {
		return ce
	}
	return channel.ErrLinkRefused
}

// closeSession tells the Vault a session ended with code.
func (cn *conn) closeSession(ctx context.Context, id sid, code channel.CloseError) error {
	c := int(code)
	return writeJSON(ctx, cn.ws, sessionCloseMsg{Type: typeSessionClose, SID: id.String(), Code: &c})
}

func writeJSON(ctx context.Context, ws *websocket.Conn, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("vault: marshal: %w", err)
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := ws.Write(wctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("vault: write: %w", err)
	}
	return nil
}

// closeWith closes the socket with a registry code and its name as the reason.
func closeWith(ws *websocket.Conn, code channel.CloseError) {
	_ = ws.Close(websocket.StatusCode(code.Code()), code.String())
}
