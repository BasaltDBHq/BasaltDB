// Package vault is the engine's one outbound connection: its WebSocket to
// the Vault (CONTRACT.md, Vault channel, The engine's socket to the Vault).
//
// A Client dials wss://relay.basaltvault.app/v1/engines/<engineId> (or the
// development override), answers CHALLENGE with an AUTH signed by the
// engine's signing key over its own Vault host, waits for READY, and keeps
// that one socket: a ping every 30 seconds, a redial when no pong comes for
// 90, and exponential backoff with full jitter from 1 to 60 seconds between
// attempts, reset after READY (unless the socket was REPLACED). One Client keeps at most one socket.
//
// Nothing the Vault sends is trusted. Every message is size-checked before
// it is read into memory (4 KiB for control messages, the ROUTE limit and
// each session's own phase limit for session bytes) and checked against
// its shape; anything else closes the socket with a registry code and the
// engine dials again.
//
// Register and Unregister put the engine's short links on the Vault
// (VC1-6), and every live link is registered again after each READY.
//
// A page that holds a relay link opens a session through the Vault: the
// engine resolves message 1's token to the link's psk (SessionLinks),
// completes the handshake and answers the page's requests with the pages
// API (Dispatcher), within the contract's limits and timeouts. Without
// both, every session's message 1 is refused as a dead token is.
package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// DefaultURL is the Vault, compiled in (CONTRACT.md: as the page origins are).
const DefaultURL = "wss://relay.basaltvault.app"

// EngineKeyHeader carries the engine's signing key SPKI when it opens its socket.
const EngineKeyHeader = "basalt-engine-key"

// Timings of CONTRACT.md, Vault channel.
const (
	// BackoffMin and BackoffMax bound the wait between attempts (VC-2).
	BackoffMin = time.Second
	BackoffMax = 60 * time.Second
	// PingInterval is how often the engine pings its socket.
	PingInterval = 30 * time.Second
	// PongTimeout is how long the engine waits for a pong before it redials.
	PongTimeout = 90 * time.Second
	// UnreachableAfter is how long without READY makes the state UNREACHABLE.
	UnreachableAfter = 30 * time.Second
	// AuthTimeout bounds dialing, CHALLENGE, AUTH and READY: the Vault's
	// challenge is valid 30 seconds, so a socket not READY by then never is.
	AuthTimeout = 30 * time.Second
	// HandshakeTimeout is how long a session may wait for its message 1.
	HandshakeTimeout = 10 * time.Second
	// MaxSessions is the most sessions the engine keeps open (CONTRACT.md, Limits).
	MaxSessions = 64
)

// State is vault.state in status.
type State string

// The states (api/mcp/tools/status.json).
const (
	StateOff         State = "OFF"
	StateConnecting  State = "CONNECTING"
	StateConnected   State = "CONNECTED"
	StateUnreachable State = "UNREACHABLE"
	StateKeyError    State = "KEY_ERROR"
)

// Status is vault in status: the state, and the engine's identity whenever
// its key file loads.
type Status struct {
	State       State
	EngineID    string
	Fingerprint string
}

// Identity is what status shows of the engine's keys.
type Identity interface {
	EngineID() string
	Fingerprint() string
}

// OffStatus is the status of an engine that does not dial out: vault is OFF
// or the pages are not the portal.
func OffStatus(id Identity) Status {
	return Status{State: StateOff, EngineID: id.EngineID(), Fingerprint: id.Fingerprint()}
}

// KeyErrorStatus is the status of an engine whose key file was refused
// (VC-36): it never dials out and shows no identity.
func KeyErrorStatus() Status { return Status{State: StateKeyError} }

// Keys are the engine's identity on its socket. *channel.EngineKeys is the
// one implementation outside tests.
type Keys interface {
	channel.Signer
	Identity
}

// Options configure a Client. Only Keys is required.
type Options struct {
	// URL is the Vault's base URL; DefaultURL when empty.
	URL string
	// Keys sign AUTH and name the engine.
	Keys Keys
	// Log receives connection events; slog.Default when nil.
	Log *slog.Logger
	// Now is the clock for State; time.Now when nil.
	Now func() time.Time
	// Jitter picks a wait in [0, ceiling]; uniform from crypto/rand when nil.
	Jitter func(ceiling time.Duration) time.Duration
	// BackoffMin, BackoffMax, PingInterval, PongTimeout, AuthTimeout,
	// UnreachableAfter and HandshakeTimeout default to the contract's
	// values when zero. Tests shorten them.
	BackoffMin       time.Duration
	BackoffMax       time.Duration
	PingInterval     time.Duration
	PongTimeout      time.Duration
	AuthTimeout      time.Duration
	UnreachableAfter time.Duration
	HandshakeTimeout time.Duration
	// RegisterTimeout defaults to RegisterTimeout when zero.
	RegisterTimeout time.Duration
	// Links are the live links registered again after every READY; none
	// when nil.
	Links Links
	// SessionLinks resolve a session's token to its live link, and Pages
	// answer the session's requests. With either nil, every session is
	// refused at message 1 (LINK_REFUSED).
	SessionLinks SessionLinks
	Pages        Dispatcher
	// IdleTimeout and SessionLifetime default to the contract's values
	// when zero. Tests shorten them.
	IdleTimeout     time.Duration
	SessionLifetime time.Duration
}

func (o *Options) defaults() {
	if o.URL == "" {
		o.URL = DefaultURL
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Jitter == nil {
		o.Jitter = fullJitter
	}
	setDefault(&o.BackoffMin, BackoffMin)
	setDefault(&o.BackoffMax, BackoffMax)
	setDefault(&o.PingInterval, PingInterval)
	setDefault(&o.PongTimeout, PongTimeout)
	setDefault(&o.AuthTimeout, AuthTimeout)
	setDefault(&o.UnreachableAfter, UnreachableAfter)
	setDefault(&o.HandshakeTimeout, HandshakeTimeout)
	setDefault(&o.RegisterTimeout, RegisterTimeout)
	setDefault(&o.IdleTimeout, IdleTimeout)
	setDefault(&o.SessionLifetime, SessionLifetime)
	if o.Links == nil {
		o.Links = noLiveLinks{}
	}
}

func setDefault(d *time.Duration, v time.Duration) {
	if *d == 0 {
		*d = v
	}
}

// links resolve session tokens: none without pages to serve them.
func (c *Client) links() SessionLinks {
	if c.opts.SessionLinks == nil || c.opts.Pages == nil {
		return noSessionLinks{}
	}
	return c.opts.SessionLinks
}

// dispatcher answers session requests; only an established session, which
// links() let through, ever reaches it.
func (c *Client) dispatcher() Dispatcher { return c.opts.Pages }

// ErrRunning is Run called while the same Client is already running: one
// Client keeps one socket.
var ErrRunning = errors.New("vault: this client is already connected or connecting")

// Client keeps the engine's one socket to the Vault. Its methods are safe
// for concurrent use.
type Client struct {
	opts    Options
	target  target
	running atomic.Bool

	mu sync.Mutex
	// cur is the READY socket, nil while there is none.
	cur *conn
	// waitingSince is when the engine last started waiting for READY: the
	// start of Run, or the end of a READY socket.
	waitingSince time.Time
}

// New returns a Client for opts. It panics without Keys, and returns an
// error for a URL it cannot dial.
func New(opts Options) (*Client, error) {
	if opts.Keys == nil {
		panic("vault: New needs the engine's keys")
	}
	opts.defaults()
	t, err := newTarget(opts.URL, opts.Keys.EngineID())
	if err != nil {
		return nil, err
	}
	return &Client{opts: opts, target: t, waitingSince: opts.Now()}, nil
}

// Status is the connection's state now, with the engine's identity.
// CONNECTING turns UNREACHABLE after UnreachableAfter without READY.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{State: StateConnecting, EngineID: c.opts.Keys.EngineID(), Fingerprint: c.opts.Keys.Fingerprint()}
	switch {
	case c.cur != nil:
		s.State = StateConnected
	case c.opts.Now().Sub(c.waitingSince) >= c.opts.UnreachableAfter:
		s.State = StateUnreachable
	}
	return s
}

// setConn makes cn the READY socket, or records that there is none (nil).
func (c *Client) setConn(cn *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil && cn == nil {
		c.waitingSince = c.opts.Now()
	}
	c.cur = cn
}

// Run keeps the socket until ctx is done, dialing again after every loss
// with backoff. It returns nil when ctx ends, and ErrRunning when this
// Client is already running.
func (c *Client) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	defer c.running.Store(false)
	c.mu.Lock()
	c.waitingSince = c.opts.Now()
	c.mu.Unlock()

	attempt := 0
	for {
		ready, err := c.connect(ctx)
		if ctx.Err() != nil {
			return nil
		}
		// READY resets the backoff, except when a newer socket for this
		// engine id replaced this one: two engines sharing a key would
		// otherwise replace each other as fast as they can dial.
		if ready && websocket.CloseStatus(err) != websocket.StatusCode(channel.ErrReplaced) {
			attempt = 0
		}
		wait := c.opts.Jitter(c.backoffCeiling(attempt))
		attempt++
		c.opts.Log.Warn("vault socket lost; dialing again", "err", err, "in", wait)
		if !sleep(ctx, wait) {
			return nil
		}
	}
}

// backoffCeiling is BackoffMin doubled once per earlier attempt, at most BackoffMax.
func (c *Client) backoffCeiling(attempt int) time.Duration {
	ceiling := c.opts.BackoffMin
	for range attempt {
		if ceiling >= c.opts.BackoffMax/2 {
			return c.opts.BackoffMax
		}
		ceiling *= 2
	}
	return min(ceiling, c.opts.BackoffMax)
}

// fullJitter is a uniform wait in [0, ceiling].
func fullJitter(ceiling time.Duration) time.Duration {
	if ceiling <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return ceiling
	}
	return time.Duration(n.Int64())
}

// sleep waits d, or until ctx ends; it reports whether d passed.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
