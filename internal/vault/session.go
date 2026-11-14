package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Link sessions (CONTRACT.md, Vault channel, Handshake and Frames): a page
// that holds a relay link's secret runs the handshake with the engine
// through the Vault, then speaks the pages API in encrypted frames. The
// engine answers each whole request with the same handlers as its local
// pages. The Vault sees only the ROUTE bytes: message 1, message 2 and
// frames, never a request or a response.

// SessionLink is the live relay link a message 1's token names.
type SessionLink struct {
	Token channel.LinkToken
	// Agent is the agent whose store holds the link.
	Agent string
	// Item is the approval or revert the link is for: a session serves
	// that item only.
	Item uuid.UUID
	// PSK keys the handshake. Lookup returns it; the engine zeroes it once
	// the tag is checked.
	PSK       channel.PSK
	ExpiresAt time.Time
}

// LogValue logs the item and the expiry only: never the token, a bearer
// handle at the Vault, or the key.
// String names the item and the expiry, never the token or the key.
func (l SessionLink) String() string {
	return "session link for " + l.Item.String() + " until " + l.ExpiresAt.UTC().Format(time.RFC3339)
}

// GoString is String: %#v would print the token and the key's fields.
func (l SessionLink) GoString() string { return l.String() }

// LogValue is the item and the expiry, as String.
func (l SessionLink) LogValue() slog.Value {
	return slog.GroupValue(slog.String("item", l.Item.String()), slog.Time("expiresAt", l.ExpiresAt))
}

// SessionLinks find the live relay link of a token. *links.Secrets, across
// the engine's agents, is the one implementation outside tests.
type SessionLinks interface {
	// Session is the live, unexpired relay link of token; false for a
	// token the engine does not hold, or one expired or revoked. It must
	// take the same time whatever it finds, and must not write to the
	// Vault: it runs on the socket's read loop.
	Session(token channel.LinkToken) (SessionLink, bool)
}

// Request is a whole request the page sent in a session.
type Request struct {
	id      int
	Method  string
	Path    string
	Headers map[string]string
	// Body is the request body, cut at MaxRequestBody+1 bytes: a body over
	// MaxRequestBody is answered 413 without the engine keeping the rest.
	Body []byte
}

// Response is the engine's answer to a Request.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

// Dispatcher answers a session's requests with the pages API: the same
// handlers, checks, statuses and bodies as on loopback (CONTRACT.md, Vault
// channel, Frames, Dispatch).
type Dispatcher interface {
	Dispatch(ctx context.Context, link SessionLink, req Request) Response
}

// Frame content types (api/mcp/vault/frame-message.schema.json).
const (
	frameRequest  = "REQUEST"
	frameResponse = "RESPONSE"
	frameContinue = "CONTINUE"
)

// frameIn is a frame's content from the page, every field optional so the
// required ones can be checked per type.
type frameIn struct {
	Type    *string            `json:"type"`
	ID      *int               `json:"id"`
	Method  *string            `json:"method"`
	Path    *string            `json:"path"`
	Headers *map[string]string `json:"headers"`
	Body    *string            `json:"body"`
	More    *bool              `json:"more"`
}

// responseOut is a RESPONSE, engine to page.
type responseOut struct {
	Type    string            `json:"type"`
	ID      int               `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	More    bool              `json:"more"`
}

// continueOut is a CONTINUE, engine to page.
type continueOut struct {
	Type string `json:"type"`
	ID   int    `json:"id"`
	Body string `json:"body"`
	More bool   `json:"more"`
}

// noSessionLinks refuses every token: an engine that serves no pages in
// sessions answers every message 1 as a dead token.
type noSessionLinks struct{}

func (noSessionLinks) Session(channel.LinkToken) (SessionLink, bool) { return SessionLink{}, false }

// handshake answers a session's message 1 in the contract's order: the
// handshake rate (every token alike), then the token, the tag and the
// point (channel.ReadHello: a dead token, a wrong psk and a bad point are
// one LINK_REFUSED, taking the same work), then the link's session limit,
// and only then the engine's public-key work for message 2.
func (cn *conn) handshake(ctx context.Context, ss *session, msg []byte) error {
	if !cn.sessions.allowHandshake(ss.token) {
		return cn.end(ctx, ss.id, channel.ErrRateLimited)
	}
	var link SessionLink
	lookup := func(t channel.LinkToken) (channel.PSK, bool) {
		l, ok := cn.c.links().Session(t)
		psk := l.PSK
		l.PSK.Zero()
		link = l
		return psk, ok
	}
	check := channel.HelloCheck{Transport: cn.transport, Lookup: lookup}
	if cn.transport == channel.TransportRelay {
		token := ss.token
		check.SessionToken = &token
	}
	resp, err := channel.ReadHello(msg, check)
	if err != nil {
		code := channel.ErrLinkRefused
		var ce channel.CloseError
		if errors.As(err, &ce) {
			code = ce
		}
		return cn.end(ctx, ss.id, code)
	}
	if cn.admit != nil {
		if code := cn.admit(ctx, link); code != 0 {
			return cn.end(ctx, ss.id, code)
		}
	}
	o := cn.c.opts
	sctx, cancel := context.WithCancel(ctx)
	est := &established{link: link, cancel: cancel, work: make(chan Request, 1)}
	now := o.Now()
	est.lastFrame.Store(now.UnixNano())
	lifetime := min(o.SessionLifetime, link.ExpiresAt.Sub(now))
	est.idle = time.AfterFunc(o.IdleTimeout, func() { cn.idleCheck(ss.id, est) })
	est.life = time.AfterFunc(max(lifetime, 0), func() { cn.endAsync(ss.id, channel.ErrTimeout) })
	ok, code := cn.sessions.establish(ss, est)
	if !ok {
		cancel()
		est.idle.Stop()
		est.life.Stop()
		if code == 0 {
			return nil // ended meanwhile: its link was revoked
		}
		return cn.end(ctx, ss.id, code)
	}
	msg2, ch, err := resp.WriteWelcome(o.Keys)
	if err != nil {
		o.Log.Error("vault session: write message 2", "err", err)
		return cn.end(ctx, ss.id, channel.ErrProtocol)
	}
	if !est.attach(ch, sctx.Done()) {
		return nil // ended while message 2 was made: its link was revoked
	}
	if err := cn.writeRoute(ctx, ss.id, msg2); err != nil {
		return err
	}
	cn.workers.Go(func() { cn.work(sctx, ss) })
	return nil
}

// attach gives the session its keys. A session that ended meanwhile (done
// closed) gets them closed, and attach reports false.
func (e *established) attach(ch *channel.Session, done <-chan struct{}) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ch = ch
	select {
	case <-done:
		ch.Close()
		return false
	default:
		return true
	}
}

// frame reads one frame of an established session on the read loop:
// decrypt it with the next counter, then take its content as part of a
// request. A whole request goes to the session's worker.
func (cn *conn) frame(ctx context.Context, ss *session, payload []byte) error {
	e := ss.est
	e.mu.Lock()
	content, err := e.ch.Open(payload)
	e.mu.Unlock()
	if err != nil {
		code := channel.ErrFrameInvalid
		var ce channel.CloseError
		if errors.As(err, &ce) {
			code = ce
		}
		return cn.end(ctx, ss.id, code)
	}
	e.lastFrame.Store(cn.c.opts.Now().UnixNano())
	req, code := e.accept(content)
	switch {
	case code != 0:
		return cn.end(ctx, ss.id, code)
	case req == nil:
		return nil
	}
	e.inFlight.Store(true)
	e.work <- *req // never blocks: one request in flight, and the worker took the last
	return nil
}

// accept takes one frame's content: a REQUEST, or a CONTINUE of the request
// being read. It returns the request once its last piece arrived, or the
// code that ends the session: PROTOCOL for content that is not one of the
// schema's shapes, a second request in flight or an id out of order;
// RATE_LIMITED past MaxRequests.
func (e *established) accept(content []byte) (*Request, channel.CloseError) {
	f, ok := parseFrameIn(content)
	if !ok {
		return nil, channel.ErrProtocol
	}
	switch *f.Type {
	case frameRequest:
		if !f.isRequest() || e.building != nil || e.inFlight.Load() {
			return nil, channel.ErrProtocol
		}
		if e.requests >= MaxRequests {
			return nil, channel.ErrRateLimited
		}
		if *f.ID != e.requests+1 {
			return nil, channel.ErrProtocol
		}
		e.requests++
		e.building = &Request{id: *f.ID, Method: *f.Method, Path: *f.Path, Headers: *f.Headers}
	case frameContinue:
		if !f.isContinue() || e.building == nil || *f.ID != e.building.id {
			return nil, channel.ErrProtocol
		}
	default:
		return nil, channel.ErrProtocol
	}
	e.appendBody(*f.Body)
	if *f.More {
		return nil, 0
	}
	req := e.building
	e.building = nil
	return req, 0
}

// appendBody keeps at most MaxRequestBody+1 bytes of a request's body.
func (e *established) appendBody(piece string) {
	room := MaxRequestBody + 1 - len(e.building.Body)
	if room <= 0 {
		return
	}
	e.building.Body = append(e.building.Body, piece[:min(room, len(piece))]...)
}

// parseFrameIn decodes a frame's content strictly: UTF-8 JSON, one object,
// no unknown field, no trailing data, a type, an id and a body and more.
func parseFrameIn(content []byte) (frameIn, bool) {
	var f frameIn
	if !utf8.Valid(content) {
		return f, false
	}
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.More() {
		return f, false
	}
	ok := f.Type != nil && f.ID != nil && *f.ID >= 1 && f.Body != nil && f.More != nil
	return f, ok
}

func (f frameIn) isRequest() bool {
	return f.Method != nil && f.Path != nil && f.Headers != nil && *f.Headers != nil
}

func (f frameIn) isContinue() bool {
	return f.Method == nil && f.Path == nil && f.Headers == nil
}

// work answers the session's requests one at a time until the session ends.
func (cn *conn) work(ctx context.Context, ss *session) {
	e := ss.est
	pages := cn.c.dispatcher()
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-e.work:
			if cn.recheck != nil {
				if code := cn.recheck(ctx, e.link); code != 0 {
					cn.endAsync(ss.id, code)
					return
				}
			}
			after := &afterAnswer{}
			dctx := context.WithValue(ctx, rotateKey{}, rotator(func(token channel.LinkToken) { cn.rotate(ss, token) }))
			dctx = context.WithValue(dctx, afterKey{}, after)
			resp := pages.Dispatch(dctx, e.link, req)
			if ctx.Err() != nil {
				after.run()
				return
			}
			err := cn.respond(ctx, ss, req.id, resp)
			after.run()
			if err != nil {
				cn.c.opts.Log.Debug("vault session: answer", "err", err)
				cn.endAsync(ss.id, channel.ErrProtocol)
				return
			}
		}
	}
}

// afterKey carries, in the context of a request a session dispatches, the
// work to run once its answer went out.
type afterKey struct{}

// afterAnswer is the work a request's handler left for after its answer.
// Only the session's worker touches it: the handler runs on the worker.
type afterAnswer struct{ fs []func() }

func (a *afterAnswer) run() {
	for _, f := range a.fs {
		f()
	}
}

// AfterAnswer runs f once the answer to the request ctx carries was sent in
// its session, or the session ended (CONTRACT.md, Vault channel, Frames: a
// reject in the session revokes the revert's link, which ends the session,
// and the page must get the reject's answer first). It reports false, and
// keeps nothing, for a request that did not come through a session, such
// as one on loopback: the caller then runs f itself.
func AfterAnswer(ctx context.Context, f func()) bool {
	a, ok := ctx.Value(afterKey{}).(*afterAnswer)
	if !ok {
		return false
	}
	a.fs = append(a.fs, f)
	return true
}

// rotateKey carries, in the context of a request a session dispatches, the
// function that moves the session to its link's new token.
type rotateKey struct{}

type rotator func(channel.LinkToken)

// RotateSession moves the session whose request ctx carries onto token, the
// token of the link its item was rotated to (CONTRACT.md, Vault channel,
// Frames: a widen in the session rotates the revert's link, and the
// session stays open under its keys). The session's later requests must
// carry the new secret, and every other session of the old token is ended
// with LINK_REFUSED. It reports false for a request that did not come
// through a session, such as one on loopback.
func RotateSession(ctx context.Context, token channel.LinkToken) bool {
	f, ok := ctx.Value(rotateKey{}).(rotator)
	if !ok {
		return false
	}
	f(token)
	return true
}

// rotate is RotateSession for ss, on its worker: only the worker reads
// est.link, and ss.token is read under the sessions' lock.
func (cn *conn) rotate(ss *session, token channel.LinkToken) {
	cn.sessions.mu.Lock()
	old := ss.token
	ss.token = token
	if cn.sessions.open[ss.id] == ss && ss.est != nil && old != token {
		cn.sessions.tally.move(old, token)
	}
	cn.sessions.mu.Unlock()
	ss.est.link.Token = token
	if old == token {
		return
	}
	if cn.endOld != nil {
		cn.endOld(old)
		return
	}
	cn.endLink(old)
}

// respond sends resp as a RESPONSE and as many CONTINUEs as its body needs,
// each frame's content at most channel.ContentMax bytes. The session is
// ready for its next request before the last frame goes, so the page's
// next request never meets one still in flight.
func (cn *conn) respond(ctx context.Context, ss *session, id int, resp Response) error {
	body := string(resp.Body)
	headers := map[string]string{}
	if resp.ContentType != "" {
		headers["content-type"] = resp.ContentType
	}
	first := true
	for {
		rest, content, err := nextPiece(body, func(piece string, more bool) any {
			if first {
				return responseOut{Type: frameResponse, ID: id, Status: resp.Status, Headers: headers, Body: piece, More: more}
			}
			return continueOut{Type: frameContinue, ID: id, Body: piece, More: more}
		})
		if err != nil {
			return err
		}
		last := rest == ""
		if last {
			ss.est.inFlight.Store(false)
		}
		if err := cn.sendFrame(ctx, ss, content); err != nil {
			return err
		}
		if last {
			return nil
		}
		body, first = rest, false
	}
}

// nextPiece cuts the longest prefix of body, at a rune boundary, whose
// frame content (build marshals it) fits in channel.ContentMax bytes.
func nextPiece(body string, build func(piece string, more bool) any) (rest string, content []byte, err error) {
	// No more than a frame's worth of body can fit, so no more is marshaled.
	n := min(len(body), channel.ContentMax)
	for n < len(body) && !utf8.RuneStart(body[n]) {
		n--
	}
	for {
		rest = body[n:]
		content, err = json.Marshal(build(body[:n], rest != ""))
		if err != nil {
			return "", nil, err
		}
		if len(content) <= channel.ContentMax {
			return rest, content, nil
		}
		// Shrink in proportion to the overshoot (escaping makes a byte of
		// body up to six of content), then back to a rune start. Every step
		// is shorter, and one rune always fits.
		n = n * channel.ContentMax / len(content)
		for n > 0 && !utf8.RuneStart(body[n]) {
			n--
		}
		if n == 0 {
			return "", nil, channel.ErrTooLarge
		}
	}
}

// sendFrame seals content as the session's next frame and routes it. A
// session ended meanwhile sends nothing. The write itself runs under the
// socket's context, never the session's: a write cut off midway would end
// the whole socket, every other session with it.
func (cn *conn) sendFrame(ctx context.Context, ss *session, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e := ss.est
	e.mu.Lock()
	frame, err := e.ch.Seal(content)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	e.lastFrame.Store(cn.c.opts.Now().UnixNano())
	return cn.writeRoute(context.WithoutCancel(ctx), ss.id, frame)
}

// writeRoute sends payload to session id's page: a ROUTE message on the
// Vault's socket, the page's own socket on DIRECT.
func (cn *conn) writeRoute(ctx context.Context, id sid, payload []byte) error {
	return cn.out.send(ctx, id, payload)
}

// idleCheck ends a session that went IdleTimeout without a frame, and
// checks again when the last frame is more recent.
func (cn *conn) idleCheck(id sid, e *established) {
	o := cn.c.opts
	since := o.Now().Sub(time.Unix(0, e.lastFrame.Load()))
	if since >= o.IdleTimeout {
		cn.endAsync(id, channel.ErrTimeout)
		return
	}
	e.idle.Reset(o.IdleTimeout - since)
}

// end ends session id with code: it stops what the session runs and tells
// the Vault. A session already ended is told again, harmlessly.
func (cn *conn) end(ctx context.Context, id sid, code channel.CloseError) error {
	if ss := cn.sessions.take(id); ss != nil {
		ss.stop()
	}
	return cn.closeSession(ctx, id, code)
}

// endAsync is end from outside the read loop (a worker, a timer, a revoked
// link): a session it no longer holds is left alone, and a failed write is
// the read loop's to notice.
func (cn *conn) endAsync(id sid, code channel.CloseError) {
	ss := cn.sessions.take(id)
	if ss == nil {
		return
	}
	ss.stop()
	if err := cn.closeSession(cn.ctx, id, code); err != nil {
		cn.c.opts.Log.Debug("vault session: close", "err", err)
	}
}

// endLink ends every session of token with LINK_REFUSED: its link was
// revoked or expired.
func (cn *conn) endLink(token channel.LinkToken) {
	for _, id := range cn.sessions.ofToken(token) {
		cn.endAsync(id, channel.ErrLinkRefused)
	}
}
