package vault

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Session limits of CONTRACT.md, Vault channel, Limits.
const (
	// MaxSessionsPerLink is the most open sessions one link may have.
	MaxSessionsPerLink = 4
	// MaxRequests is the most requests one session may make.
	MaxRequests = 64
	// HandshakesPerLink is the most message 1s one link token may send
	// within HandshakeWindow.
	HandshakesPerLink = 20
	// HandshakeWindow is the window HandshakesPerLink counts over.
	HandshakeWindow = 10 * time.Minute
	// IdleTimeout ends a session without a frame for this long.
	IdleTimeout = 5 * time.Minute
	// SessionLifetime ends a session this long after its handshake, and
	// never later than its link's expiry.
	SessionLifetime = 30 * time.Minute
	// MaxRequestBody is a request body's limit, as on loopback: over it the
	// pages answer 413. The engine keeps one byte more, never the rest.
	MaxRequestBody = 16 << 10
	// maxTrackedTokens bounds the handshake counters: a Vault that opens
	// sessions for ever new tokens cannot make them grow without bound.
	maxTrackedTokens = 4096
)

// phase is where a session is.
type phase int

const (
	// phaseNone is a sid the engine does not hold.
	phaseNone phase = iota
	// phaseHello waits for message 1.
	phaseHello
	// phaseOpen is established: frames either way.
	phaseOpen
)

// Tally counts the sessions open on every transport of one engine, so the
// per-engine and per-link limits hold across the Vault's socket and the
// direct listener together (CONTRACT.md, Direct transport, Limits). One
// Tally is given to the Client and to Direct; a table made without one
// counts only its own sessions.
type Tally struct {
	mu          sync.Mutex
	total       int
	established map[channel.LinkToken]int
}

// NewTally returns an empty Tally.
func NewTally() *Tally { return &Tally{established: map[channel.LinkToken]int{}} }

// reserve takes one of the engine's session slots; false at the limit.
func (t *Tally) reserve() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total >= MaxSessions {
		return false
	}
	t.total++
	return true
}

// release gives a slot back, and the link's if the session was established.
func (t *Tally) release(token channel.LinkToken, established bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total--
	if established {
		if t.established[token]--; t.established[token] <= 0 {
			delete(t.established, token)
		}
	}
}

// move gives an established session's link slot from old to new: a widen
// rotated its token.
func (t *Tally) move(old, next channel.LinkToken) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.established[old]--; t.established[old] <= 0 {
		delete(t.established, old)
	}
	t.established[next]++
}

// establish takes one of the link's slots; false at the limit.
func (t *Tally) establish(token channel.LinkToken) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.established[token] >= MaxSessionsPerLink {
		return false
	}
	t.established[token]++
	return true
}

// sessions are the sessions the Vault opened on one socket. The read loop
// opens, handshakes and reads them; workers, timers and revocations end
// them, so the map is locked.
type sessions struct {
	timeout time.Duration
	now     func() time.Time
	tally   *Tally

	mu   sync.Mutex
	open map[sid]*session
	// handshakes are the times of each token's recent message 1s.
	handshakes map[channel.LinkToken][]time.Time
}

// session is one session: waiting for message 1, or established (est set).
type session struct {
	id       sid
	token    channel.LinkToken
	openedAt time.Time
	est      *established
}

// established is a session after the handshake.
type established struct {
	link SessionLink
	// cancel ends the worker and any dispatch in flight.
	cancel context.CancelFunc
	// timers end the session when idle or at its lifetime.
	idle, life *time.Timer
	// lastFrame is when a frame last went either way (UnixNano).
	lastFrame atomic.Int64
	// inFlight is set while a request is being answered.
	inFlight atomic.Bool
	// work carries a whole request from the read loop to the worker.
	work chan Request

	// mu guards ch: the read loop opens frames, the worker seals them.
	mu sync.Mutex
	ch *channel.Session

	// The request being read; only the read loop uses these.
	requests int
	building *Request
}

func newSessions(timeout time.Duration, now func() time.Time, tally *Tally) *sessions {
	if tally == nil {
		tally = NewTally()
	}
	return &sessions{
		timeout: timeout, now: now, tally: tally,
		open: map[sid]*session{}, handshakes: map[channel.LinkToken][]time.Time{},
	}
}

// add opens a session. It returns the code to close it with at once
// instead: SESSION_LIMIT over the engine's limit, PROTOCOL for a sid the
// Vault already opened (which is ended as well).
func (s *sessions) add(id sid, token channel.LinkToken) (channel.CloseError, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, dup := s.open[id]; dup {
		s.drop(id, old)
		return channel.ErrProtocol, old
	}
	if !s.tally.reserve() {
		return channel.ErrSessionLimit, nil
	}
	s.open[id] = &session{id: id, token: token, openedAt: s.now()}
	return 0, nil
}

// drop removes a session from the table and the tally; s.mu is held.
func (s *sessions) drop(id sid, ss *session) {
	delete(s.open, id)
	s.tally.release(ss.token, ss.est != nil)
}

// take removes a session and returns it, nil when it is not held: whoever
// takes it ends it, once.
func (s *sessions) take(id sid) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.open[id]
	if ss != nil {
		s.drop(id, ss)
	}
	return ss
}

// takeAll removes every session, as when the socket ends.
func (s *sessions) takeAll() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*session, 0, len(s.open))
	for id, ss := range s.open {
		out = append(out, ss)
		s.drop(id, ss)
	}
	return out
}

// ofToken lists the sessions of token, waiting or established.
func (s *sessions) ofToken(token channel.LinkToken) []sid {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sid
	for id, ss := range s.open {
		if ss.token == token {
			out = append(out, id)
		}
	}
	return out
}

// expired removes and returns the sessions that waited for message 1 past
// the handshake timeout.
func (s *sessions) expired() []sid {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sid
	now := s.now()
	for id, ss := range s.open {
		if ss.est == nil && now.Sub(ss.openedAt) >= s.timeout {
			out = append(out, id)
			s.drop(id, ss)
		}
	}
	return out
}

// lookup is a session's phase, with the session, before any of its next
// ROUTE payload is read.
func (s *sessions) lookup(id sid) (phase, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.open[id]
	switch {
	case !ok:
		return phaseNone, nil
	case ss.est == nil:
		return phaseHello, ss
	}
	return phaseOpen, ss
}

// late reports whether a session waiting for message 1 has waited past
// the handshake timeout.
func (s *sessions) late(ss *session) bool {
	return s.now().Sub(ss.openedAt) >= s.timeout
}

// allowHandshake counts a message 1 for token and reports whether it is
// within HandshakesPerLink per HandshakeWindow. Every token counts, held
// or not, so the answer says nothing of whether the engine holds it.
func (s *sessions) allowHandshake(token channel.LinkToken) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	recent := s.recent(token, now)
	if len(recent) == 0 && len(s.handshakes) >= maxTrackedTokens {
		s.forgetOld(now)
		if len(s.handshakes) >= maxTrackedTokens {
			return false
		}
	}
	if len(recent) >= HandshakesPerLink {
		s.handshakes[token] = recent
		return false
	}
	s.handshakes[token] = append(recent, now)
	return true
}

// recent is token's message 1s within the window; the caller holds mu.
func (s *sessions) recent(token channel.LinkToken, now time.Time) []time.Time {
	times := s.handshakes[token]
	i := 0
	for i < len(times) && now.Sub(times[i]) >= HandshakeWindow {
		i++
	}
	if i == len(times) {
		delete(s.handshakes, token)
		return nil
	}
	return times[i:]
}

// forgetOld drops every token with no message 1 in the window; the caller
// holds mu.
func (s *sessions) forgetOld(now time.Time) {
	for token := range s.handshakes {
		s.recent(token, now)
	}
}

// establish makes a waiting session established, unless it ended
// meanwhile (a revoked link). Over MaxSessionsPerLink it reports
// SESSION_LIMIT and leaves the session waiting for the caller to end.
func (s *sessions) establish(ss *session, est *established) (bool, channel.CloseError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open[ss.id] != ss {
		return false, 0
	}
	if !s.tally.establish(ss.token) {
		return false, channel.ErrSessionLimit
	}
	ss.est = est
	return true, 0
}

// stop ends what a session runs: its worker, its timers and its keys.
func (ss *session) stop() {
	e := ss.est
	if e == nil {
		return
	}
	e.cancel()
	e.idle.Stop()
	e.life.Stop()
	e.mu.Lock()
	if e.ch != nil {
		e.ch.Close()
	}
	e.mu.Unlock()
}
