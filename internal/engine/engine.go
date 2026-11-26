// Package engine is the edge engine: one service per machine, running as its
// own OS user, serving each agent MCP over that agent's own Unix socket
// (owner decision #2). A connection is served only when the peer's OS user
// is the one configured for the agent; the agent's MCP client reaches the
// socket through the stdio shim and never holds a database credential.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/peercred"
)

// Agent is one agent the engine serves on its own socket.
type Agent struct {
	Name string
	// UID is the only peer uid allowed on the socket.
	UID        uint32
	SocketPath string
	Server     Server
}

// PeerUIDFunc reads the uid of a connection's peer.
type PeerUIDFunc func(*net.UnixConn) (uint32, error)

// Engine serves agents over their sockets.
type Engine struct {
	log     *slog.Logger
	mcp     MCP
	sockets Sockets
	agents  []Agent
	peerUID PeerUIDFunc
	// drains holds, per agent, a slot for each refused connection being
	// drained; when all are taken a refused peer is closed at once.
	drains map[string]chan struct{}
	// drainFor bounds how long one refused connection is drained.
	drainFor time.Duration

	restart Restart
	gate    *CallGate
}

// refusedDrains is how many refused connections of one agent are drained
// at a time (refusePeer); more are answered and closed at once.
const refusedDrains = 8

// New returns an engine for agents, listening on their sockets through s
// and writing its refusals through m. It panics on a nil logger, m or s, no
// agents, or an agent without a socket or server.
func New(log *slog.Logger, m MCP, s Sockets, agents []Agent) *Engine {
	if log == nil || m == nil || s == nil || len(agents) == 0 {
		panic("engine: logger, MCP, sockets and at least one agent required")
	}
	for _, a := range agents {
		if a.Name == "" || a.SocketPath == "" || a.Server == nil {
			panic("engine: agent needs a name, a socket path and a server")
		}
	}
	e := &Engine{log: log, mcp: m, sockets: s, agents: agents, peerUID: peercred.UID, gate: NewCallGate(), drainFor: refuseDrain}
	return e.WithRefusedDrains(refusedDrains)
}

// WithRefusedDrains sets how many refused connections of one agent are
// drained at a time (tests).
func (e *Engine) WithRefusedDrains(n int) *Engine {
	e.drains = make(map[string]chan struct{}, len(e.agents))
	for _, a := range e.agents {
		e.drains[a.Name] = make(chan struct{}, n)
	}
	return e
}

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

// Serve listens on every agent's socket and serves connections until ctx is
// done, then closes the listeners and open connections and removes the
// socket files.
// WithRestart turns on the restart onto a new binary: when o.Upgrade
// returns, Serve stops between calls and returns ErrRestart.
func (e *Engine) WithRestart(o Restart) *Engine {
	e.restart = o.withDefaults()
	return e
}

// Serve serves every agent's socket until ctx is done, then returns nil.
// With WithRestart, it returns ErrRestart once it stopped for an upgrade.
func (e *Engine) Serve(ctx context.Context) error {
	listeners := make([]*net.UnixListener, 0, len(e.agents))
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			for _, ln := range listeners {
				ln.Close()
			}
		})
	}
	for _, a := range e.agents {
		ln, err := e.sockets.ListenSocket(a.SocketPath)
		if err != nil {
			closeAll()
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		listeners = append(listeners, ln)
		e.log.Info("serving agent", "agent", a.Name, "socket", a.SocketPath, "uid", a.UID)
	}

	stopped := ctx // the caller's: done means stop, never restart
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// draining ends when the engine stops taking calls for a restart: every
	// connection is then read only briefly more.
	draining, drain := context.WithCancel(context.Background())
	defer drain()
	var wg sync.WaitGroup
	for i, a := range e.agents {
		wg.Go(func() { e.acceptLoop(ctx, draining, a, listeners[i]) })
	}
	served := make(chan struct{})
	go func() { wg.Wait(); close(served) }()
	if !e.awaitUpgrade(ctx) {
		closeAll()
		<-served
		return nil
	}
	e.log.Info("a new basalt binary is installed: restarting onto it between calls")
	if !e.gate.closeWhenIdle(ctx, e.restart.IdleWait) {
		closeAll()
		<-served
		return nil
	}
	closeAll()
	drain()
	e.finishDrain(ctx, cancel, served)
	if stopped.Err() != nil {
		// Stopped during the drain: a stop, not a restart.
		return nil
	}
	return ErrRestart
}

// WithGate makes the engine share g with the other servers whose requests
// a restart waits for (the person socket, page sessions).
func (e *Engine) WithGate(g *CallGate) *Engine {
	e.gate = g
	return e
}

// awaitUpgrade reports whether the engine should restart onto a new binary
// (true) or ctx ended first (false).
func (e *Engine) awaitUpgrade(ctx context.Context) bool {
	if e.restart.Upgrade != nil && e.restart.Upgrade(ctx) == nil && ctx.Err() == nil {
		return true
	}
	<-ctx.Done()
	return false
}

// finishDrain waits for every connection to end, up to DrainWait, then
// cancels the calls still running.
func (e *Engine) finishDrain(ctx context.Context, cancel context.CancelFunc, served <-chan struct{}) {
	wctx, stop := context.WithTimeout(ctx, e.restart.DrainWait)
	defer stop()
	select {
	case <-served:
	case <-wctx.Done():
	}
	// Person requests and page sessions are counted by the gate too.
	if e.gate.waitIdle(wctx) {
		<-served
		return
	}
	if ctx.Err() == nil {
		e.log.Warn("calls still running after the drain wait are cancelled for the restart", "wait", e.restart.DrainWait)
	}
	cancel()
	<-served
}

// unixAccepter is the listener acceptLoop reads (tests fake it).
type unixAccepter interface {
	AcceptUnix() (*net.UnixConn, error)
}

// Accept backoff after a temporary error, as net/http does.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func (e *Engine) acceptLoop(ctx, draining context.Context, a Agent, ln unixAccepter) {
	var conns sync.WaitGroup
	defer conns.Wait()
	var backoff time.Duration
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if !e.sockets.TemporaryAccept(err) {
				e.log.Error("accept", "agent", a.Name, "err", err)
				return
			}
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			e.log.Warn("accept failed, retrying", "agent", a.Name, "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		conns.Go(func() { e.serveConn(ctx, draining, a, conn) })
	}
}

func (e *Engine) serveConn(ctx, draining context.Context, a Agent, conn *net.UnixConn) {
	defer conn.Close()
	uid, err := e.peerUID(conn)
	if err != nil {
		e.log.Warn("refused connection: no peer credentials", "agent", a.Name, "err", err)
		return
	}
	if uid != a.UID {
		e.log.Warn("refused connection from another OS user", "agent", a.Name, "peerUid", uid, "wantUid", a.UID)
		e.refusePeer(ctx, conn, a.Name, uid)
		return
	}
	// Closing the connection on shutdown unblocks the server's read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	gate := connGate{CallGate: e.gate, conn: conn}
	stopDrain := context.AfterFunc(draining, gate.stopReading)
	defer stopDrain()
	err = a.Server.ServeGated(ctx, conn, conn, gate)
	if err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
		e.log.Warn("connection ended", "agent", a.Name, "err", err)
	}
}

// refuseDrain bounds how long a refused connection is read before it is
// closed: closing with the client's request unread would reset it.
const (
	refuseDrain      = 2 * time.Second
	refuseDrainBytes = 64 << 10
)

// refusePeer answers a peer of another OS user with one refusal line that
// says who may use the socket, then reads (and drops) what it sent, so the
// shim sees the refusal instead of a reset. Nothing it sent is served. At
// most refusedDrains connections of one agent are drained at a time; past
// that, and once ctx is done, the connection is closed after the line.
func (e *Engine) refusePeer(ctx context.Context, conn *net.UnixConn, agentName string, uid uint32) {
	msg := fmt.Sprintf("the basalt engine refused this connection: the socket of agent %q serves only that agent's OS user "+
		"(osUser in the engine config), and this process runs as uid %d. Start the MCP client as the agent's OS user, "+
		"or ask the person to set the agent's osUser in the engine config", agentName, uid)
	if err := e.mcp.WritePeerRefused(conn, msg); err != nil {
		return
	}
	_ = conn.CloseWrite()
	slots := e.drains[agentName]
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		return // enough refused peers are drained already
	}
	_ = conn.SetReadDeadline(time.Now().Add(e.drainFor))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, refuseDrainBytes))
}
