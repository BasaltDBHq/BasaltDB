package vault

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// sessions are the sessions the Vault opened on one socket, each in its
// phase. Only the socket's read loop uses them, so they need no lock.
//
// Until VC1-7 a session has one phase: waiting for message 1, whose ROUTE
// payload must be exactly 99 bytes. VC1-7 adds the established phase, whose
// payloads are frames of at most channel.FrameMax bytes.
type sessions struct {
	open    map[sid]pending
	timeout time.Duration
	now     func() time.Time
}

// pending is a session waiting for its message 1.
type pending struct {
	token    channel.LinkToken
	openedAt time.Time
}

func newSessions(timeout time.Duration, now func() time.Time) sessions {
	return sessions{open: map[sid]pending{}, timeout: timeout, now: now}
}

// add opens a session. It returns the code to close it with at once
// instead: SESSION_LIMIT over the engine's limit, PROTOCOL for a sid the
// Vault already opened (which is dropped as well).
func (s *sessions) add(id sid, token channel.LinkToken) channel.CloseError {
	if _, dup := s.open[id]; dup {
		delete(s.open, id)
		return channel.ErrProtocol
	}
	if len(s.open) >= MaxSessions {
		return channel.ErrSessionLimit
	}
	s.open[id] = pending{token: token, openedAt: s.now()}
	return 0
}

// remove forgets a session.
func (s *sessions) remove(id sid) { delete(s.open, id) }

// expired removes and returns the sessions that waited for message 1 past
// the handshake timeout.
func (s *sessions) expired() []sid {
	var out []sid
	now := s.now()
	for id, p := range s.open {
		if now.Sub(p.openedAt) >= s.timeout {
			out = append(out, id)
			delete(s.open, id)
		}
	}
	return out
}

// late reports whether session id has waited for its message 1 past the
// handshake timeout.
func (s *sessions) late(id sid) bool {
	p, ok := s.open[id]
	return ok && s.now().Sub(p.openedAt) >= s.timeout
}

// limit is the most payload bytes the next ROUTE for id may carry, before
// any of it is read: message 1's exact size for a session waiting for it,
// else a frame's (bytes of a session already closed, dropped once read).
func (s *sessions) limit(id sid) (maxLen int, token channel.LinkToken, awaitingHello bool) {
	p, ok := s.open[id]
	if !ok {
		return channel.FrameMax, channel.LinkToken{}, false
	}
	return channel.Message1Len, p.token, true
}
