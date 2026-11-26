// Package vaulttest is a fake Vault for hermetic tests: it speaks the Vault
// side of CONTRACT.md, Vault channel, on a loopback HTTP server.
//
// It authenticates engine sockets (/v1/engines/<engineId>), binds link tokens
// to the engine that registered them (LINK_CONFLICT for any other engine),
// pairs page sockets (/v1/links/<linkToken>) with their engine and forwards
// session bytes both ways as opaque ROUTE messages. It never holds a key that
// opens a session and never looks inside a session message.
//
// Hooks make it a hostile Vault (VC1-12): Tamper sees every session message
// and decides what is delivered (drop, replay, reorder, splice, reflect);
// Inject and InjectControl send messages of the test's own; LoseState forgets
// every binding; OnRegister can stall, refuse or force a registration so a
// test can race two engines for one token; Bind routes a token to any engine;
// OnUnregister and OnSessionClose drop, refuse or alter those messages; and
// SuppressPongs stops answering an engine's pings.
package vaulttest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
)

// readLimit is the transport's own cap. It sits above every protocol limit
// so the fake sees an oversized message and closes with TOO_LARGE itself.
const readLimit = 4 * MaxRoute

// writeTimeout bounds one write to a socket.
const writeTimeout = 5 * time.Second

// Options configure a Vault. The zero value is the contract's behavior.
type Options struct {
	// Now is the clock for link expiry; time.Now when nil.
	Now func() time.Time
	// ChallengeTTL is how long the engine has to answer CHALLENGE; ChallengeTTL when zero.
	ChallengeTTL time.Duration
	// Challenge makes the challenge bytes; crypto/rand when nil. A hostile
	// test can make it repeat one.
	Challenge func() [ChallengeLen]byte
	// MaxLinksPerEngine caps live links per engine (LINK_LIMIT); MinLinksPerEngine when zero.
	MaxLinksPerEngine int
	// MaxSessionsPerLink and MaxSessionsPerEngine, when set, close a page
	// socket over them with SESSION_LIMIT (the Vault's own numbers; off by default).
	MaxSessionsPerLink   int
	MaxSessionsPerEngine int
	// Tamper, when set, decides what is delivered for each session message.
	Tamper Tamper
	// OnRegister, when set, runs before each REGISTER_LINK is handled.
	OnRegister RegisterHook
	// OnUnregister, when set, runs before each UNREGISTER_LINK is handled.
	OnUnregister UnregisterHook
	// OnSessionClose, when set, sees each SESSION_CLOSE either way.
	OnSessionClose SessionCloseHook
	// OnEngineMessage, when set, sees every message an engine sends on its
	// socket (AUTH included), as received, before it is handled.
	OnEngineMessage EngineMessageHook
}

// Vault is the fake. Start one with New; Close stops it.
type Vault struct {
	opts Options
	srv  *httptest.Server
	host string

	// ctx ends every socket when Close is called; wg counts the goroutines
	// the fake starts (handlers and closes) so Close returns after them.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	stopped  bool                   // Close was called: refuse new sockets
	noPong   map[string]bool        // engine ids whose pings go unanswered
	pings    map[string]int         // pings received per engine id
	engines  map[string]*engineConn // live authenticated socket per engine id
	links    map[string]*link       // link token -> binding
	sessions map[SID]*session
}

type link struct {
	engineID  string
	expiresAt time.Time
}

type engineConn struct {
	id   string
	conn *websocket.Conn
}

type session struct {
	sid    SID
	token  string
	engine *engineConn
	page   *websocket.Conn
	closed bool
}

// New starts a fake Vault on a loopback port.
func New(opts Options) *Vault {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ChallengeTTL == 0 {
		opts.ChallengeTTL = ChallengeTTL
	}
	if opts.Challenge == nil {
		opts.Challenge = randomChallenge
	}
	if opts.MaxLinksPerEngine == 0 {
		opts.MaxLinksPerEngine = MinLinksPerEngine
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := &Vault{
		opts:     opts,
		ctx:      ctx,
		cancel:   cancel,
		noPong:   map[string]bool{},
		pings:    map[string]int{},
		engines:  map[string]*engineConn{},
		links:    map[string]*link{},
		sessions: map[SID]*session{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/engines/{engineId}", v.tracked(v.serveEngine))
	mux.HandleFunc("GET /v1/links/{linkToken}", v.tracked(v.servePage))
	v.srv = httptest.NewServer(mux)
	v.host = strings.TrimPrefix(v.srv.URL, "http://")
	return v
}

// Close ends every socket at once, an engine still in CHALLENGE included,
// stops the server and returns when every goroutine of the fake has ended.
func (v *Vault) Close() {
	v.mu.Lock()
	v.stopped = true
	v.mu.Unlock()
	v.cancel()
	v.srv.Close()
	v.wg.Wait()
}

// tracked counts a handler in wg and gives it a context that also ends on
// Close. After Close it refuses the request.
func (v *Vault) tracked(h func(ctx context.Context, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		if v.stopped {
			v.mu.Unlock()
			http.Error(w, "closed", http.StatusServiceUnavailable)
			return
		}
		v.wg.Add(1)
		v.mu.Unlock()
		defer v.wg.Done()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(v.ctx, cancel) //nolint:contextcheck // v.ctx is the Vault's lifetime; it only cancels ctx, which derives from r.Context()
		defer stop()
		h(ctx, w, r)
	}
}

// goClose closes conn with code in a counted goroutine: a close waits for the
// peer's answer, which must not hold up the caller.
func (v *Vault) goClose(conn *websocket.Conn, code websocket.StatusCode) {
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		closeWith(conn, code)
	}()
}

// Host is the Vault host an engine signs into AUTH: the override's host:port.
func (v *Vault) Host() string { return v.host }

// URL is the ws:// base URL, the engine's vaultUrl override.
func (v *Vault) URL() string { return "ws://" + v.host }

// EngineURL is the engine socket URL for an engine id.
func (v *Vault) EngineURL(engineID string) string { return v.URL() + "/v1/engines/" + engineID }

// LinkURL is the page socket URL for a link token.
func (v *Vault) LinkURL(linkToken string) string { return v.URL() + "/v1/links/" + linkToken }

// Connected reports whether engineID has a live authenticated socket.
func (v *Vault) Connected(engineID string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.engines[engineID]
	return ok
}

// LinkOwner is the engine id a live token is bound to.
func (v *Vault) LinkOwner(linkToken string) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	l := v.liveLink(linkToken)
	if l == nil {
		return "", false
	}
	return l.engineID, true
}

// SessionInfo describes an open session.
type SessionInfo struct {
	SID       SID
	LinkToken string
	EngineID  string
}

// Sessions lists the open sessions.
func (v *Vault) Sessions() []SessionInfo {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]SessionInfo, 0, len(v.sessions))
	for _, s := range v.sessions {
		out = append(out, s.info())
	}
	return out
}

func (s *session) info() SessionInfo {
	return SessionInfo{SID: s.sid, LinkToken: s.token, EngineID: s.engine.id}
}

// --- engine socket ---

func (v *Vault) serveEngine(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	engineID := r.PathValue("engineId")
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OnPingReceived: func(context.Context, []byte) bool { return v.pong(engineID) },
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(readLimit)

	if code := v.authenticate(ctx, conn, r.PathValue("engineId"), r.Header.Get(EngineKeyHeader)); code != 0 {
		closeWith(conn, code)
		return
	}
	e := &engineConn{id: r.PathValue("engineId"), conn: conn}
	v.mu.Lock()
	old := v.engines[e.id]
	v.engines[e.id] = e
	v.mu.Unlock()
	if old != nil {
		v.dropEngine(ctx, old, CloseReplaced)
	}
	if err := v.writeJSON(ctx, e, Ready{Type: TypeReady}); err != nil {
		v.dropEngine(ctx, e, CloseNormal)
		return
	}
	v.dropEngine(ctx, e, v.engineLoop(ctx, e))
}

// authenticate runs open, CHALLENGE and AUTH. It returns a close code on failure.
func (v *Vault) authenticate(ctx context.Context, conn *websocket.Conn, engineID, keyHeader string) websocket.StatusCode {
	key, der, err := ParseEngineKey(keyHeader)
	if err != nil || EngineID(der) != engineID {
		return CloseAuthFailed
	}
	raw := v.opts.Challenge()
	challenge := b64(raw[:])
	if err := writeJSONConn(ctx, conn, Challenge{Type: TypeChallenge, Challenge: challenge}); err != nil {
		return CloseNormal
	}
	// A Read whose context ends closes the socket without a code, so the
	// deadline closes it with AUTH_FAILED instead.
	fired := make(chan struct{})
	late := time.AfterFunc(v.opts.ChallengeTTL, func() {
		defer close(fired)
		closeWith(conn, CloseAuthFailed)
	})
	typ, data, err := conn.Read(ctx)
	if !late.Stop() {
		<-fired
		return CloseAuthFailed
	}
	if err != nil {
		return CloseAuthFailed
	}
	v.observe(engineID, typ, data)
	if typ != websocket.MessageText {
		return CloseProtocol
	}
	if len(data) > MaxControl {
		return CloseTooLarge
	}
	var auth struct {
		Type    string `json:"type"`
		Version *int   `json:"version"`
		Sig     string `json:"sig"`
	}
	if err := strictjson.Decode(data, &auth); err != nil || auth.Type != TypeAuth || auth.Version == nil {
		return CloseProtocol
	}
	if *auth.Version != int(Version) {
		return CloseUnsupportedVersion
	}
	if !VerifySig(key, AuthInput(challenge, v.host), auth.Sig) {
		return CloseAuthFailed
	}
	return 0
}

// engineLoop reads the engine's messages until the socket ends or breaks the
// protocol. It returns the code to close the engine socket with.
func (v *Vault) engineLoop(ctx context.Context, e *engineConn) websocket.StatusCode {
	for {
		typ, data, err := e.conn.Read(ctx)
		if err != nil {
			return CloseNormal
		}
		v.observe(e.id, typ, data)
		code := v.engineMessage(ctx, e, typ, data)
		if code != 0 {
			return code
		}
	}
}

func (v *Vault) engineMessage(ctx context.Context, e *engineConn, typ websocket.MessageType, data []byte) websocket.StatusCode {
	if typ == websocket.MessageBinary {
		return v.engineRoute(ctx, e, data)
	}
	if len(data) > MaxControl {
		return CloseTooLarge
	}
	t, err := controlType(data)
	if err != nil {
		return CloseProtocol
	}
	switch t {
	case TypeRegisterLink:
		return v.register(ctx, e, data)
	case TypeUnregisterLink:
		return v.unregister(ctx, e, data)
	case TypeSessionClose:
		return v.engineSessionClose(ctx, e, data)
	default:
		// CHALLENGE, AUTH after READY, OK, ERROR, SESSION_OPEN or an unknown type.
		return CloseProtocol
	}
}

func (v *Vault) register(ctx context.Context, e *engineConn, data []byte) websocket.StatusCode {
	var m RegisterLink
	if err := strictjson.Decode(data, &m); err != nil || !validRef(m.Ref) || !validLinkToken(m.LinkToken) {
		return CloseProtocol
	}
	expiresAt, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return CloseProtocol
	}
	verdict := Verdict{}
	if v.opts.OnRegister != nil {
		verdict = v.opts.OnRegister(e.id, m)
	}
	if code, done := v.applyVerdict(ctx, e, m.Ref, verdict); done {
		return code
	}
	if code := v.bind(e.id, m.LinkToken, expiresAt); code != "" {
		return v.answer(ctx, e, Error{Type: TypeError, Ref: m.Ref, Code: code})
	}
	return v.answer(ctx, e, OK{Type: TypeOK, Ref: m.Ref})
}

// applyVerdict answers a request as a hook's verdict says. done is false for
// the zero verdict: the fake then handles the request itself.
func (v *Vault) applyVerdict(ctx context.Context, e *engineConn, ref int64, verdict Verdict) (websocket.StatusCode, bool) {
	switch {
	case verdict.Drop:
		return 0, true
	case verdict.Code != "":
		return v.answer(ctx, e, Error{Type: TypeError, Ref: ref, Code: verdict.Code}), true
	case verdict.ForceOK:
		return v.answer(ctx, e, OK{Type: TypeOK, Ref: ref}), true
	}
	return 0, false
}

// bind records the token for engineID, or returns the ERROR code that refuses it.
func (v *Vault) bind(engineID, token string, expiresAt time.Time) string {
	now := v.opts.Now()
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxExpiryAhead)) {
		return ErrInvalidExpiry
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if l := v.liveLink(token); l != nil {
		if l.engineID != engineID {
			return ErrLinkConflict
		}
		l.expiresAt = expiresAt
		return ""
	}
	if v.liveLinksOf(engineID) >= v.opts.MaxLinksPerEngine {
		return ErrLinkLimit
	}
	v.links[token] = &link{engineID: engineID, expiresAt: expiresAt}
	return ""
}

func (v *Vault) unregister(ctx context.Context, e *engineConn, data []byte) websocket.StatusCode {
	var m UnregisterLink
	if err := strictjson.Decode(data, &m); err != nil || !validRef(m.Ref) || !validLinkToken(m.LinkToken) {
		return CloseProtocol
	}
	verdict := Verdict{}
	if v.opts.OnUnregister != nil {
		verdict = v.opts.OnUnregister(e.id, m)
	}
	if code, done := v.applyVerdict(ctx, e, m.Ref, verdict); done {
		return code
	}
	v.mu.Lock()
	l := v.liveLink(m.LinkToken)
	if l != nil && l.engineID != e.id {
		v.mu.Unlock()
		return v.answer(ctx, e, Error{Type: TypeError, Ref: m.Ref, Code: ErrLinkConflict})
	}
	delete(v.links, m.LinkToken)
	var pages []*session
	for _, s := range v.sessions {
		if s.token == m.LinkToken && s.engine.id == e.id {
			pages = append(pages, s)
		}
	}
	v.mu.Unlock()
	for _, s := range pages {
		v.endSession(ctx, s, CloseLinkUnknown, false)
	}
	return v.answer(ctx, e, OK{Type: TypeOK, Ref: m.Ref})
}

func (v *Vault) engineSessionClose(ctx context.Context, e *engineConn, data []byte) websocket.StatusCode {
	var m SessionClose
	if err := strictjson.Decode(data, &m); err != nil {
		return CloseProtocol
	}
	sid, err := ParseSID(m.SID)
	if err != nil || !engineCloseCodes[m.Code] {
		return CloseProtocol
	}
	s := v.sessionOf(e, sid)
	if s == nil {
		return v.answer(ctx, e, Error{Type: TypeError, Code: ErrUnknownSession})
	}
	code, deliver := v.sessionCloseHook(s, ToPage, websocket.StatusCode(m.Code))
	if !deliver {
		return 0
	}
	v.endSession(ctx, s, code, false)
	return 0
}

func (v *Vault) engineRoute(ctx context.Context, e *engineConn, data []byte) websocket.StatusCode {
	if len(data) > MaxRoute {
		return CloseTooLarge
	}
	sid, payload, err := ParseRoute(data)
	switch {
	case errors.Is(err, errUnsupportedVersion):
		return CloseUnsupportedVersion
	case err != nil:
		return CloseProtocol
	}
	s := v.sessionOf(e, sid)
	if s == nil {
		return v.answer(ctx, e, Error{Type: TypeError, Code: ErrUnknownSession})
	}
	v.forward(ctx, Message{Session: s.info(), Dir: ToPage, Data: payload})
	return 0
}

// answer writes a control message to the engine; a failed write ends the socket.
func (v *Vault) answer(ctx context.Context, e *engineConn, msg any) websocket.StatusCode {
	if err := v.writeJSON(ctx, e, msg); err != nil {
		return CloseNormal
	}
	return 0
}

// dropEngine closes an engine socket and every session routed to it, whose
// pages are told ENGINE_OFFLINE.
func (v *Vault) dropEngine(ctx context.Context, e *engineConn, code websocket.StatusCode) {
	v.mu.Lock()
	if v.engines[e.id] == e {
		delete(v.engines, e.id)
	}
	var open []*session
	for _, s := range v.sessions {
		if s.engine == e {
			open = append(open, s)
		}
	}
	v.mu.Unlock()
	for _, s := range open {
		v.endSession(ctx, s, CloseEngineOffline, false)
	}
	// Closing waits for the engine's answer; the caller may hold up a newer socket.
	v.goClose(e.conn, code)
}

// --- page socket ---

func (v *Vault) servePage(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(readLimit)
	if r.Header.Get("Origin") != PortalOrigin {
		closeWith(conn, CloseProtocol)
		return
	}
	s, code := v.openSession(r.PathValue("linkToken"), conn)
	if code != 0 {
		closeWith(conn, code)
		return
	}
	open := SessionOpen{Type: TypeSessionOpen, SID: s.sid.String(), LinkToken: s.token}
	if err := v.writeJSON(ctx, s.engine, open); err != nil {
		v.endSession(ctx, s, CloseEngineOffline, false)
		return
	}
	v.pageLoop(ctx, s)
}

// openSession pairs a page socket with the engine its token is bound to.
func (v *Vault) openSession(token string, page *websocket.Conn) (*session, websocket.StatusCode) {
	v.mu.Lock()
	defer v.mu.Unlock()
	l := v.liveLink(token)
	if l == nil {
		return nil, CloseLinkUnknown
	}
	e := v.engines[l.engineID]
	if e == nil {
		return nil, CloseEngineOffline
	}
	if v.overSessionLimit(token, e) {
		return nil, CloseSessionLimit
	}
	s := &session{sid: newSID(), token: token, engine: e, page: page}
	v.sessions[s.sid] = s
	return s, 0
}

func (v *Vault) overSessionLimit(token string, e *engineConn) bool {
	perLink, perEngine := 0, 0
	for _, s := range v.sessions {
		if s.engine != e {
			continue
		}
		perEngine++
		if s.token == token {
			perLink++
		}
	}
	return (v.opts.MaxSessionsPerLink > 0 && perLink >= v.opts.MaxSessionsPerLink) ||
		(v.opts.MaxSessionsPerEngine > 0 && perEngine >= v.opts.MaxSessionsPerEngine)
}

// pageLoop forwards the page's binary messages to the engine until either side ends.
func (v *Vault) pageLoop(ctx context.Context, s *session) {
	for {
		typ, data, err := s.page.Read(ctx)
		if err != nil {
			v.endSession(ctx, s, pageCloseCode(err), true)
			return
		}
		code := websocket.StatusCode(0)
		switch {
		case typ != websocket.MessageBinary:
			code = CloseProtocol
		case len(data) > MaxFrame:
			code = CloseTooLarge
		}
		if code != 0 {
			v.endSession(ctx, s, code, true)
			return
		}
		v.forward(ctx, Message{Session: s.info(), Dir: ToEngine, Data: data})
	}
}

// pageCloseCode is the code a page socket ended with, as SESSION_CLOSE carries
// it: the page's own close code when it is 1000 or a registry code, else 1000.
func pageCloseCode(err error) websocket.StatusCode {
	code := websocket.CloseStatus(err)
	if sessionCloseCode(code) {
		return code
	}
	return CloseNormal
}

// endSession ends a session once: it closes the page socket with code and,
// when tellEngine is set (the page side ended), sends the engine SESSION_CLOSE.
func (v *Vault) endSession(ctx context.Context, s *session, code websocket.StatusCode, tellEngine bool) {
	v.mu.Lock()
	if s.closed {
		v.mu.Unlock()
		return
	}
	s.closed = true
	delete(v.sessions, s.sid)
	v.mu.Unlock()
	if tellEngine {
		if told, deliver := v.sessionCloseHook(s, ToEngine, code); deliver {
			_ = v.writeJSON(ctx, s.engine, SessionClose{Type: TypeSessionClose, SID: s.sid.String(), Code: int(told)})
		}
	}
	// Closing blocks until the page answers or a timeout; never under v.mu.
	v.goClose(s.page, code)
}

// --- helpers ---

// liveLink is the binding of token, dropping it if it expired. Callers hold v.mu.
func (v *Vault) liveLink(token string) *link {
	l := v.links[token]
	if l == nil {
		return nil
	}
	if !v.opts.Now().Before(l.expiresAt) {
		delete(v.links, token)
		return nil
	}
	return l
}

// liveLinksOf counts engineID's live links. Callers hold v.mu.
func (v *Vault) liveLinksOf(engineID string) int {
	n := 0
	for token, l := range v.links {
		if l.engineID == engineID && v.liveLink(token) != nil {
			n++
		}
	}
	return n
}

// sessionOf is an open session routed to e; another engine's sid is unknown to e.
func (v *Vault) sessionOf(e *engineConn, sid SID) *session {
	v.mu.Lock()
	defer v.mu.Unlock()
	s := v.sessions[sid]
	if s == nil || s.engine != e {
		return nil
	}
	return s
}

func (v *Vault) writeJSON(ctx context.Context, e *engineConn, msg any) error {
	return writeJSONConn(ctx, e.conn, msg)
}

func writeJSONConn(ctx context.Context, conn *websocket.Conn, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return writeConn(ctx, conn, websocket.MessageText, data)
}

func writeConn(ctx context.Context, conn *websocket.Conn, typ websocket.MessageType, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := conn.Write(ctx, typ, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// closeWith closes a socket with code and its registry name as the reason.
func closeWith(conn *websocket.Conn, code websocket.StatusCode) {
	_ = conn.Close(code, CloseNames[int(code)])
}

func randomChallenge() [ChallengeLen]byte {
	var c [ChallengeLen]byte
	_, _ = rand.Read(c[:])
	return c
}

func newSID() SID {
	var s SID
	_, _ = rand.Read(s[:])
	return s
}
