// Package dial reaches a plugin entry over the transport its verified
// manifest names: the one place the engine and basalt plugin check choose a
// transport. It imports the adapters; the protocol-neutral host does not.
package dial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin/jsonrpc"
)

// Transport names in a manifest's endpoint.
const (
	TransportStdio   = "jsonrpc-stdio"
	TransportUnix    = "jsonrpc-unix"
	TransportConnect = "connectrpc"
)

// SocketEnv is the one environment variable a local socket plugin
// (jsonrpc-unix, local connectrpc) is started with: the absolute path of
// the Unix socket it listens on. It is how the socket is handed to the
// plugin at start. Nothing else of the engine's environment is passed.
const SocketEnv = "BASALT_PLUGIN_SOCKET"

// Timing of a socket plugin's start.
const (
	socketPoll = 10 * time.Millisecond
	// stopWait bounds the wait for a killed child to be reaped.
	stopWait = 2 * time.Second
)

// ErrNoSocket: a socket plugin exited, or the start deadline passed, before
// its socket appeared.
var ErrNoSocket = errors.New("the plugin did not listen on its socket")

// Options are what reaching an entry needs besides its verified copy.
type Options struct {
	// SocketPath is where a local socket plugin is told to listen. The
	// caller makes its directory, reachable by the engine's user only, and
	// keeps the path short enough for a Unix socket. Unused otherwise.
	SocketPath string
	// CredentialFile is the entry's auth.credentialFile, remote only.
	CredentialFile string
	// Stderr receives a local plugin's stderr; nil discards it.
	Stderr io.Writer
}

// Entry reaches the installed copy v: a remote plugin through the
// connectrpc adapter (TLS to the declared host only); a local
// jsonrpc-stdio plugin as a child process speaking on its stdin and stdout;
// a local jsonrpc-unix or connectrpc plugin as a child process started with
// SocketEnv only, connected to once its socket appears. A local child gets
// no other environment. ctx bounds the start and the connection.
// Errors name the entry, and the adapters' errors name only a host or a
// socket's file name.
func Entry(ctx context.Context, k plugin.EntryKey, v plugin.Verified, o Options) (plugin.Transport, error) {
	m := v.Manifest
	if r := m.Endpoint.Remote; r != nil {
		return wrap(k)(connect.Dial(ctx, *r, m.Network.Egress, o.CredentialFile))
	}
	l := m.Endpoint.Local
	if l == nil {
		return nil, fmt.Errorf("plugin %s: the manifest has no endpoint", k)
	}
	command := filepath.Join(v.Dir, filepath.FromSlash(l.Command))
	switch l.Transport {
	case TransportStdio:
		t, err := jsonrpc.Spawn(ctx, command, l.Args, o.Stderr)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: its command could not be started", k)
		}
		return t, nil
	case TransportUnix:
		return wrap(k)(startSocket(ctx, command, l.Args, o, func(ctx context.Context) (plugin.Transport, error) {
			return jsonrpc.Dial(ctx, o.SocketPath)
		}))
	case TransportConnect:
		return wrap(k)(startSocket(ctx, command, l.Args, o, func(ctx context.Context) (plugin.Transport, error) {
			return connect.DialLocal(ctx, o.SocketPath)
		}))
	}
	return nil, fmt.Errorf("plugin %s: transport %q is not served", k, l.Transport)
}

func wrap(k plugin.EntryKey) func(plugin.Transport, error) (plugin.Transport, error) {
	return func(t plugin.Transport, err error) (plugin.Transport, error) {
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", k, err)
		}
		return t, nil
	}
}

// startSocket starts a socket plugin, waits for its socket, and connects
// with dial. On any failure the child is stopped.
func startSocket(ctx context.Context, command string, args []string, o Options,
	dial func(context.Context) (plugin.Transport, error),
) (plugin.Transport, error) {
	if o.SocketPath == "" || !filepath.IsAbs(o.SocketPath) {
		return nil, errors.New("a socket plugin needs an absolute socket path")
	}
	// A stale socket from an earlier run would be dialed before the child
	// listens.
	if err := os.Remove(o.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("socket %s cannot be replaced", filepath.Base(o.SocketPath))
	}
	cmd := exec.Command(command, args...)
	cmd.Env = []string{SocketEnv + "=" + o.SocketPath}
	if o.Stderr != nil {
		cmd.Stderr = o.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.New("its command could not be started")
	}
	p := &proc{cmd: cmd, socket: o.SocketPath, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.exited) }()
	if err := p.waitSocket(ctx); err != nil {
		p.stop()
		return nil, err
	}
	t, err := dial(ctx)
	if err != nil {
		p.stop()
		return nil, err
	}
	return &socketTransport{Transport: t, p: p}, nil
}

// proc is a socket plugin's child process.
type proc struct {
	cmd    *exec.Cmd
	socket string
	exited chan struct{}
	once   sync.Once
}

func (p *proc) waitSocket(ctx context.Context) error {
	tick := time.NewTicker(socketPoll)
	defer tick.Stop()
	for {
		if fi, err := os.Lstat(p.socket); err == nil && fi.Mode().Type() == os.ModeSocket {
			return nil
		}
		select {
		case <-p.exited:
			return ErrNoSocket
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrNoSocket, ctx.Err())
		case <-tick.C:
		}
	}
}

// stop kills the child, reaps it and removes its socket.
func (p *proc) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Kill()
		select {
		case <-p.exited:
		case <-time.After(stopWait):
		}
		_ = os.Remove(p.socket)
	})
}

// socketTransport closes the connection, then stops the child: as for
// jsonrpc.Spawn, a graceful stop is the shutdown call made before Close.
type socketTransport struct {
	plugin.Transport
	p *proc
}

func (t *socketTransport) Close() error {
	err := t.Transport.Close()
	t.p.stop()
	return err
}
