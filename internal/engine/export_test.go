package engine

import "time"

// WithRefuseDrain sets how long a refused connection is drained before it
// is closed (tests).
func (e *Engine) WithRefuseDrain(d time.Duration) *Engine {
	e.drainFor = d
	return e
}

// WithPeerUID replaces how the peer uid is read (tests).
func (e *Engine) WithPeerUID(f PeerUIDFunc) *Engine {
	e.peerUID = f
	return e
}
