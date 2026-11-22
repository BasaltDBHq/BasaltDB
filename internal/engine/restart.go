package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// ErrRestart is what Serve and Run return after they stopped to restart
// onto an upgraded binary: every agent connection was drained and every
// socket closed. The caller runs the new binary (CONTRACT.md, Next steps,
// Engine restarts).
var ErrRestart = errors.New("the engine stopped to restart onto the upgraded binary")

// UpgradeFunc blocks until the engine should restart onto a new binary and
// returns nil then, or returns ctx's error when ctx ends first.
type UpgradeFunc func(ctx context.Context) error

const (
	// DefaultIdleWait is how long a restart waits for a moment when no
	// agent call runs, longer than the longest wait a call may ask for (110
	// seconds), so only calls that keep overlapping can hold it off.
	DefaultIdleWait = 2 * time.Minute
	// DefaultDrainWait is how long the calls still running when the idle
	// wait ran out may finish; past it they are cancelled, and their
	// transactions roll back.
	DefaultDrainWait = 2 * time.Minute
	// drainReadGrace is how long a drained connection is still read, so the
	// requests the shim had already sent are answered ErrCodeRestarting
	// rather than dropped.
	drainReadGrace = 250 * time.Millisecond
)

// RestartOptions turn on the restart onto a new binary.
type RestartOptions struct {
	// Upgrade says when to restart; nil turns the restart off.
	Upgrade UpgradeFunc
	// Handoff reaches the connect service and the collected database for
	// a connect-only agent; the zero value is the contract's.
	Handoff HandoffOptions
	// IdleWait and DrainWait default to DefaultIdleWait and
	// DefaultDrainWait.
	IdleWait  time.Duration
	DrainWait time.Duration
	// PluginStderr is where local plugins' stderr goes (basalt engine
	// --plugin-debug), on a foreground engine only; nil discards it. It
	// rides along with the restart options because both are how
	// basalt engine runs this engine.
	PluginStderr io.Writer
	// StartedBy is why this engine started: "hand" (the default when
	// empty), "mcp" (basalt mcp found it down) or "crash" (the supervisor
	// restarted it). It is carried here for the status report.
	StartedBy string
	// StableAfter is how long the engine serves before it removes the
	// supervisor's record of giving up; zero means DefaultStableAfter.
	StableAfter time.Duration
}

// DefaultStableAfter is how long an engine serves before an earlier
// give-up of its supervisor is forgotten (last-stop.json is removed).
const DefaultStableAfter = 10 * time.Second

// LastStopFile is the supervisor's record of giving up, in the state
// directory (basalt engine --supervise).
const LastStopFile = "last-stop.json"

// startedByOrHand is v, or "hand" when empty.
func startedByOrHand(v string) string {
	if v == "" {
		return "hand"
	}
	return v
}

func (o RestartOptions) withDefaults() RestartOptions {
	if o.IdleWait <= 0 {
		o.IdleWait = DefaultIdleWait
	}
	if o.DrainWait <= 0 {
		o.DrainWait = DefaultDrainWait
	}
	return o
}

// callGate counts the agent calls running on every connection. Once it is
// closed it admits none, so the engine can stop between calls.
type callGate struct {
	mu     sync.Mutex
	busy   int
	closed bool
	// idle gets a value whenever busy drops to zero.
	idle chan struct{}
}

func newCallGate() *callGate { return &callGate{idle: make(chan struct{}, 1)} }

func (g *callGate) Begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.busy++
	return true
}

func (g *callGate) End() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.busy--
	if g.busy > 0 {
		return
	}
	select {
	case g.idle <- struct{}{}:
	default:
	}
}

// tryClose closes the gate when no call runs; force closes it anyway. It
// reports whether the gate is now closed.
func (g *callGate) tryClose(force bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy == 0 || force {
		g.closed = true
	}
	return g.closed
}

// isClosed reports whether the gate admits no more calls.
func (g *callGate) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// closeWhenIdle closes the gate at the first moment no call runs, or when
// wait runs out, whichever comes first; false when ctx ended first (the
// gate is then left open).
func (g *callGate) closeWhenIdle(ctx context.Context, wait time.Duration) bool {
	t := time.NewTimer(wait)
	defer t.Stop()
	for !g.tryClose(false) {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return g.tryClose(true)
		case <-g.idle:
		}
	}
	return true
}

// waitIdle waits until no admitted call runs; false when ctx ended first.
func (g *callGate) waitIdle(ctx context.Context) bool {
	for {
		g.mu.Lock()
		busy := g.busy
		g.mu.Unlock()
		if busy == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-g.idle:
		}
	}
}

// gatedDispatcher counts each page-session request (an approval or a revert
// relayed through the Vault or the direct listener) in the gate, and
// answers UNAVAILABLE with nothing run once the gate is closed.
type gatedDispatcher struct {
	gate *callGate
	next vault.Dispatcher
}

func (d gatedDispatcher) Dispatch(ctx context.Context, link vault.SessionLink, req vault.Request) vault.Response {
	if !d.gate.Begin() {
		return restartingResponse()
	}
	defer d.gate.End()
	return d.next.Dispatch(ctx, link, req)
}

// restartingResponse is the pages API's error for a request the engine did
// not run because it is restarting.
func restartingResponse() vault.Response {
	body, err := json.Marshal(map[string]string{
		"code":    agent.CodeUnavailable,
		"message": "the basalt engine is restarting onto the upgraded binary and did not run this request; nothing was run: try again in a few seconds",
	})
	if err != nil {
		panic(err) // a map of strings
	}
	return vault.Response{Status: http.StatusServiceUnavailable, ContentType: "application/json", Body: body}
}

// connGate is the gate as one connection sees it: once the gate is closed,
// the connection is read only for drainReadGrace after its last answer.
type connGate struct {
	*callGate
	conn *net.UnixConn
}

func (c connGate) End() {
	c.callGate.End()
	if c.isClosed() {
		c.stopReading()
	}
}

// stopReading lets the connection be read for drainReadGrace more, so the
// requests already sent are answered, then ends it.
func (c connGate) stopReading() {
	_ = c.conn.SetReadDeadline(time.Now().Add(drainReadGrace))
}
