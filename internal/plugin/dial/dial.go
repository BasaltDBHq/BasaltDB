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
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/child"
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

// socketPoll is how often a socket plugin's start looks for its socket.
const socketPoll = 10 * time.Millisecond

// socketFile is the socket's name in its directory.
const socketFile = "p.sock"

// socketDirMode: the engine's user only.
const socketDirMode = 0o700

// MaxSocketPath is the longest Unix socket path this OS takes, in bytes:
// sun_path is 104 bytes on macOS and the BSDs and 108 on Linux, with the
// terminating NUL.
var MaxSocketPath = maxSocketPath(runtime.GOOS)

func maxSocketPath(goos string) int {
	const darwinSunPath, linuxSunPath = 104, 108
	if goos == "linux" {
		return linuxSunPath - 1
	}
	return darwinSunPath - 1
}

// ErrNoSocket: a socket plugin exited, or the start deadline passed, before
// its socket appeared.
var ErrNoSocket = errors.New("the plugin did not listen on its socket")

// Options are what reaching an entry needs besides its verified copy.
type Options struct {
	// SocketBase is where a local socket plugin's socket directory is made:
	// a new directory per start, created by the engine's user with mode
	// 0700, holding only the socket, and removed when the plugin stops. It
	// is never a directory the plugin's files live in. Empty means the OS
	// temporary directory. The socket's path must fit MaxSocketPath.
	SocketBase string
	// CredentialFile is the entry's auth.credentialFile, remote only.
	CredentialFile string
	// Stderr receives a local plugin's stderr; nil discards it.
	Stderr io.Writer
}

// Entry reaches the installed copy v: a remote plugin through the
// connectrpc adapter (TLS to the declared host only); a local
// jsonrpc-stdio plugin as a child process speaking on its stdin and stdout;
// a local jsonrpc-unix or connectrpc plugin as a child process started with
// SocketEnv only, connected to once its socket appears. A local child runs
// in its own process group with the installed copy as its working
// directory and no other environment; closing the transport kills the
// group. ctx bounds the start and the connection. Errors name the entry,
// and the adapters' errors name only a host or a socket's file name.
//
// A local plugin's transport has an Exited method whose channel is closed
// once its process has exited.
func Entry(ctx context.Context, k plugin.EntryKey, v plugin.Verified, o Options) (plugin.Transport, error) {
	m := v.Manifest
	if r := m.Endpoint.Remote; r != nil {
		return wrap(k)(connect.Dial(ctx, *r, m.Network.Egress, o.CredentialFile))
	}
	l := m.Endpoint.Local
	if l == nil {
		return nil, fmt.Errorf("plugin %s: the manifest has no endpoint", k)
	}
	spec := child.Spec{Path: filepath.Join(v.Dir, filepath.FromSlash(l.Command)), Args: l.Args, Dir: v.Dir, Stderr: o.Stderr}
	switch l.Transport {
	case TransportStdio:
		t, err := jsonrpc.Spawn(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: its command could not be started", k)
		}
		return t, nil
	case TransportUnix:
		return wrap(k)(startSocket(ctx, spec, o.SocketBase, jsonrpc.Dial))
	case TransportConnect:
		return wrap(k)(startSocket(ctx, spec, o.SocketBase, connect.DialLocal))
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

// socketDir makes a new socket directory under base and returns the
// socket's path in it. The path's length is checked before anything is
// made.
func socketDir(base string) (dir, path string, err error) {
	if base == "" {
		base = os.TempDir()
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return "", "", err
	}
	// MkdirTemp adds its pattern and a random suffix of up to 10 digits.
	const pattern, suffix = "bp", 10
	if n := len(filepath.Join(base, pattern)) + suffix + len("/"+socketFile); n > MaxSocketPath {
		return "", "", fmt.Errorf("a socket path under %s would be %d bytes; Unix sockets take at most %d here, so set TMPDIR to a shorter directory", base, n, MaxSocketPath)
	}
	dir, err = os.MkdirTemp(base, pattern)
	if err != nil {
		return "", "", errors.New("the plugin's socket directory could not be made")
	}
	// MkdirTemp makes it 0700 whatever the umask; say so where it matters.
	if err := os.Chmod(dir, socketDirMode); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", errors.New("the plugin's socket directory could not be made private")
	}
	return dir, filepath.Join(dir, socketFile), nil
}

// startSocket starts a socket plugin in a new socket directory, waits for
// its socket, and connects with dial. On any failure the child is stopped
// and the directory removed.
func startSocket(ctx context.Context, spec child.Spec, base string,
	dial func(context.Context, string) (plugin.Transport, error),
) (plugin.Transport, error) {
	dir, sock, err := socketDir(base)
	if err != nil {
		return nil, err
	}
	spec.Env = []string{SocketEnv + "=" + sock}
	p, err := child.Start(spec)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("its command could not be started")
	}
	st := &socketTransport{p: p, dir: dir}
	if err := waitSocket(ctx, sock, p.Exited()); err != nil {
		st.stop()
		return nil, err
	}
	t, err := dial(ctx, sock)
	if err != nil {
		st.stop()
		return nil, err
	}
	st.Transport = t
	return st, nil
}

func waitSocket(ctx context.Context, sock string, exited <-chan struct{}) error {
	tick := time.NewTicker(socketPoll)
	defer tick.Stop()
	for {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode().Type() == os.ModeSocket {
			return nil
		}
		select {
		case <-exited:
			return ErrNoSocket
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrNoSocket, ctx.Err())
		case <-tick.C:
		}
	}
}

// socketTransport closes the connection, then kills the child's process
// group and removes the socket directory: as for jsonrpc.Spawn, a graceful
// stop is the shutdown call made before Close.
type socketTransport struct {
	plugin.Transport
	p   *child.Process
	dir string
}

func (t *socketTransport) stop() {
	t.p.Stop()
	_ = os.RemoveAll(t.dir)
}

// Close implements plugin.Transport.
func (t *socketTransport) Close() error {
	err := t.Transport.Close()
	t.stop()
	return err
}

// Exited is closed once the plugin's process has exited.
func (t *socketTransport) Exited() <-chan struct{} { return t.p.Exited() }
