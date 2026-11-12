package vaulttest

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
)

// Direction is which way a session message travels.
type Direction int

const (
	// ToEngine is a page message on its way to the engine (as a ROUTE).
	ToEngine Direction = iota + 1
	// ToPage is an engine message on its way to the page.
	ToPage
)

// Message is one session message the Vault received, as opaque bytes: the
// page's message as sent, or the engine's ROUTE payload.
type Message struct {
	Session SessionInfo
	Dir     Direction
	Data    []byte
}

// Delivery is one message the Vault sends: Data to the session SID in Dir.
// SID may name any open session, of any engine.
type Delivery struct {
	SID  SID
	Dir  Direction
	Data []byte
}

// Forward is the honest delivery of m: unchanged, to its own session, onward.
func Forward(m Message) Delivery {
	return Delivery{SID: m.Session.SID, Dir: m.Dir, Data: m.Data}
}

// Tamper decides what the Vault delivers for one received session message.
// Return nil to drop it, the same Delivery twice to duplicate it, a held
// earlier message after this one to reorder, a Delivery to another SID to
// splice, or the message with the opposite Dir to reflect it to its sender.
// It is called from several goroutines at once and must be safe for that.
type Tamper func(m Message) []Delivery

// Verdict is what OnRegister makes of a REGISTER_LINK. The zero value lets
// the fake handle it as the contract says.
type Verdict struct {
	// Drop sends no answer at all.
	Drop bool
	// Code answers ERROR with this code and binds nothing.
	Code string
	// ForceOK answers OK and binds nothing.
	ForceOK bool
}

// RegisterHook runs before the fake handles a REGISTER_LINK from engineID.
// It may block: a test races two engines for one token by holding the real
// engine's registration here until a rival's went through.
type RegisterHook func(engineID string, m RegisterLink) Verdict

// UnregisterHook runs before the fake handles an UNREGISTER_LINK from
// engineID. ForceOK answers OK and leaves the binding (and its pages) as they are.
type UnregisterHook func(engineID string, m UnregisterLink) Verdict

// SessionCloseHook sees a SESSION_CLOSE: Dir ToEngine is the Vault telling
// the engine a page ended, Dir ToPage the engine's SESSION_CLOSE, which closes
// the page with its code. It returns the code to use instead and whether to
// deliver it at all. A dropped ToPage close leaves the session open; a dropped
// ToEngine close ends the session at the Vault without telling the engine.
type SessionCloseHook func(s SessionInfo, dir Direction, code websocket.StatusCode) (websocket.StatusCode, bool)

// EngineMessageHook sees one message an engine sent on its socket. It is
// called from several goroutines at once and must be safe for that.
type EngineMessageHook func(engineID string, typ websocket.MessageType, data []byte)

func (v *Vault) observe(engineID string, typ websocket.MessageType, data []byte) {
	if v.opts.OnEngineMessage != nil {
		v.opts.OnEngineMessage(engineID, typ, data)
	}
}

func (v *Vault) sessionCloseHook(s *session, dir Direction, code websocket.StatusCode) (websocket.StatusCode, bool) {
	if v.opts.OnSessionClose == nil {
		return code, true
	}
	return v.opts.OnSessionClose(s.info(), dir, code)
}

// SuppressPongs makes the Vault stop (or resume) answering engineID's pings,
// so a test sees the engine give up after 90 seconds without a pong.
func (v *Vault) SuppressPongs(engineID string, suppress bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.noPong[engineID] = suppress
}

// Pings is how many pings engineID's sockets have sent.
func (v *Vault) Pings(engineID string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.pings[engineID]
}

// pong counts a ping and reports whether to answer it.
func (v *Vault) pong(engineID string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pings[engineID]++
	return !v.noPong[engineID]
}

// ErrNoSession is returned for a delivery to a session that is not open.
var ErrNoSession = errors.New("vaulttest: no such session")

// ErrNoEngine is returned for a message to an engine with no live socket.
var ErrNoEngine = errors.New("vaulttest: engine not connected")

// forward runs Tamper (when set) over m and delivers the result.
func (v *Vault) forward(ctx context.Context, m Message) {
	deliveries := []Delivery{Forward(m)}
	if v.opts.Tamper != nil {
		deliveries = v.opts.Tamper(m)
	}
	for _, d := range deliveries {
		_ = v.deliver(ctx, d)
	}
}

// Inject delivers a message of the test's own: Data to the page of session
// d.SID (ToPage), or as a ROUTE with d.SID to that session's engine (ToEngine).
func (v *Vault) Inject(d Delivery) error {
	return v.deliver(context.Background(), d)
}

func (v *Vault) deliver(ctx context.Context, d Delivery) error {
	v.mu.Lock()
	s := v.sessions[d.SID]
	v.mu.Unlock()
	if s == nil {
		return ErrNoSession
	}
	if d.Dir == ToPage {
		return writeConn(ctx, s.page, websocket.MessageBinary, d.Data)
	}
	return writeConn(ctx, s.engine.conn, websocket.MessageBinary, Route(d.SID, d.Data))
}

// InjectRaw sends engineID's live socket any message, binary or text: a forged
// SESSION_OPEN, OK, ERROR or SESSION_CLOSE, a ROUTE for an unknown sid, or junk.
func (v *Vault) InjectRaw(engineID string, typ websocket.MessageType, data []byte) error {
	v.mu.Lock()
	e := v.engines[engineID]
	v.mu.Unlock()
	if e == nil {
		return ErrNoEngine
	}
	return writeConn(context.Background(), e.conn, typ, data)
}

// InjectControl sends engineID a control message of the test's own, as JSON.
func (v *Vault) InjectControl(engineID string, msg any) error {
	v.mu.Lock()
	e := v.engines[engineID]
	v.mu.Unlock()
	if e == nil {
		return ErrNoEngine
	}
	return v.writeJSON(context.Background(), e, msg)
}

// LoseState forgets every token binding, as a Vault that lost its storage.
// Sockets and open sessions stay; an engine recovers by registering again
// after its next READY.
func (v *Vault) LoseState() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.links = map[string]*link{}
}

// Bind routes linkToken to engineID until expiresAt, overriding any binding:
// a hostile Vault that hands a token to an engine that does not hold its link.
func (v *Vault) Bind(linkToken, engineID string, expiresAt time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.links[linkToken] = &link{engineID: engineID, expiresAt: expiresAt}
}

// DisconnectEngine closes engineID's socket with code (as a restart or a
// network drop would) and its sessions' pages with ENGINE_OFFLINE.
func (v *Vault) DisconnectEngine(engineID string, code websocket.StatusCode) {
	v.mu.Lock()
	e := v.engines[engineID]
	v.mu.Unlock()
	if e == nil {
		return
	}
	v.dropEngine(context.Background(), e, code)
}

// CloseSession ends a session as the Vault: the page is closed with code and
// the engine is sent SESSION_CLOSE with it (a forged close, for the engine).
func (v *Vault) CloseSession(sid SID, code websocket.StatusCode) error {
	v.mu.Lock()
	s := v.sessions[sid]
	v.mu.Unlock()
	if s == nil {
		return ErrNoSession
	}
	v.endSession(context.Background(), s, code, true)
	return nil
}
