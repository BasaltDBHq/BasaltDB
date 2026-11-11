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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

const (
	// socketDirMode lets agents' OS users reach their sockets.
	socketDirMode = 0o755
	// socketMode lets any local user connect; the peer uid check on accept
	// is what authorizes a connection.
	socketMode = 0o666
)

// Agent is one agent the engine serves on its own socket.
type Agent struct {
	Name string
	// UID is the only peer uid allowed on the socket.
	UID        uint32
	SocketPath string
	Server     *mcp.Server
}

// PeerUIDFunc reads the uid of a connection's peer.
type PeerUIDFunc func(*net.UnixConn) (uint32, error)

// Engine serves agents over their sockets.
type Engine struct {
	log     *slog.Logger
	agents  []Agent
	peerUID PeerUIDFunc
}

// New returns an engine for agents. It panics on a nil logger, no agents, or
// an agent without a socket or server.
func New(log *slog.Logger, agents []Agent) *Engine {
	if log == nil || len(agents) == 0 {
		panic("engine: logger and at least one agent required")
	}
	for _, a := range agents {
		if a.Name == "" || a.SocketPath == "" || a.Server == nil {
			panic("engine: agent needs a name, a socket path and a server")
		}
	}
	return &Engine{log: log, agents: agents, peerUID: peercred.UID}
}

// WithPeerUID replaces how the peer uid is read (tests).
func (e *Engine) WithPeerUID(f PeerUIDFunc) *Engine {
	e.peerUID = f
	return e
}

// Serve listens on every agent's socket and serves connections until ctx is
// done, then closes the listeners and open connections and removes the
// socket files.
func (e *Engine) Serve(ctx context.Context) error {
	listeners := make([]*net.UnixListener, 0, len(e.agents))
	closeAll := func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}
	for _, a := range e.agents {
		ln, err := listenSocket(a.SocketPath)
		if err != nil {
			closeAll()
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		listeners = append(listeners, ln)
		e.log.Info("serving agent", "agent", a.Name, "socket", a.SocketPath, "uid", a.UID)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i, a := range e.agents {
		wg.Go(func() { e.acceptLoop(ctx, a, listeners[i]) })
	}
	<-ctx.Done()
	closeAll()
	wg.Wait()
	return nil
}

func (e *Engine) acceptLoop(ctx context.Context, a Agent, ln *net.UnixListener) {
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				e.log.Error("accept", "agent", a.Name, "err", err)
			}
			return
		}
		conns.Go(func() { e.serveConn(ctx, a, conn) })
	}
}

func (e *Engine) serveConn(ctx context.Context, a Agent, conn *net.UnixConn) {
	defer conn.Close()
	uid, err := e.peerUID(conn)
	if err != nil {
		e.log.Warn("refused connection: no peer credentials", "agent", a.Name, "err", err)
		return
	}
	if uid != a.UID {
		e.log.Warn("refused connection from another OS user", "agent", a.Name, "peerUid", uid, "wantUid", a.UID)
		return
	}
	// Closing the connection on shutdown unblocks the server's read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := a.Server.Serve(ctx, conn, conn); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		e.log.Warn("connection ended", "agent", a.Name, "err", err)
	}
}

// listenSocket listens on path, replacing a stale socket file but never any
// other kind of file, and opens the socket to local users.
func listenSocket(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), socketDirMode); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(path)
	switch {
	case err == nil && fi.Mode()&os.ModeSocket == 0:
		return nil, fmt.Errorf("%s exists and is not a socket; refusing to replace it", path)
	case err == nil:
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, socketMode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
