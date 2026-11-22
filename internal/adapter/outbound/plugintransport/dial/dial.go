// Package dial reaches a plugin entry over the transport its verified
// manifest names: the one place the engine and basalt plugin check choose a
// transport. It imports the adapters; the protocol-neutral host does not.
package dial

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/connect"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/jsonrpc"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
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
	// temporary directory. The socket's path must fit MaxSocketPath, and the
	// base and every directory above it must pass plugin.CheckSocketBase.
	SocketBase string
	// Runs, when set, records each local process started (child.Runs), so
	// the engine's next start can reap one a crash left running. The engine
	// sets it; basalt plugin check does not.
	Runs *child.Runs
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
func Entry(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, o Options) (pluginmodel.Transport, error) {
	m := v.Manifest
	if r := m.Endpoint.Remote; r != nil {
		return wrap(k)(connect.Dial(ctx, *r, m.Network.Egress, o.CredentialFile))
	}
	l := m.Endpoint.Local
	if l == nil {
		return nil, fmt.Errorf("plugin %s: the manifest has no endpoint", k)
	}
	spec := child.Spec{Path: filepath.Join(v.Dir, filepath.FromSlash(l.Command)), Args: l.Args, Dir: v.Dir, Stderr: o.Stderr, Runs: o.Runs}
	switch l.Transport {
	case TransportStdio:
		t, err := jsonrpc.Spawn(ctx, spec)
		if err != nil {
			if o.Runs != nil && errors.Is(err, child.ErrNotRecorded) {
				return nil, fmt.Errorf("plugin %s: %w", k, err)
			}
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

func wrap(k pluginmodel.EntryKey) func(pluginmodel.Transport, error) (pluginmodel.Transport, error) {
	return func(t pluginmodel.Transport, err error) (pluginmodel.Transport, error) {
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", k, err)
		}
		return t, nil
	}
}

// socketDirPrefix and socketDirRandom make a socket directory's name: the
// prefix and socketDirRandom random bytes in hex.
const (
	socketDirPrefix = "bp"
	socketDirRandom = 8
)

// socketDirName is a new socket directory's name, unpredictable to another
// user.
func socketDirName() (string, error) {
	b := make([]byte, socketDirRandom)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return socketDirPrefix + hex.EncodeToString(b), nil
}

// socketDir makes a new socket directory under base and returns the
// socket's path in it. The path's length and the base's ownership and modes
// (plugin.CheckSocketBase: no one but the engine's user or root can write it
// or a directory above it, unless root owns that directory and its sticky
// bit is set) are checked before anything is made. The directory itself is
// made by makeSocketDir: a random name, refused if anything is there, and
// its owner and mode checked on the directory opened, not by its path.
func socketDir(base string) (dir, path string, err error) {
	if base == "" {
		base = os.TempDir()
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return "", "", err
	}
	if err := socketPathFits(base); err != nil {
		return "", "", err
	}
	if err := pluginmodel.CheckSocketBase(base); err != nil {
		var ve *pluginmodel.VerifyError
		if errors.As(err, &ve) {
			return "", "", fmt.Errorf("plugin socket directories are made under %s, but %s %s; "+
				"a directory there may be writable by others only when root owns it and its sticky bit is set, as for /tmp. "+
				"Set TMPDIR to a directory only you can write, such as a new directory of mode 0700 in your home directory", base, ve.File, ve.Why)
		}
		return "", "", err
	}
	// Every symlink on the way is root's (CheckSocketBase); the directory is
	// made in, and its path named from, the directory they lead to.
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", "", errors.New("the plugin socket base " + base + " cannot be read")
	}
	if err := socketPathFits(resolved); err != nil {
		return "", "", err
	}
	name, err := socketDirName()
	if err != nil {
		return "", "", errors.New("the plugin's socket directory could not be named")
	}
	if err := makeSocketDir(resolved, name); err != nil {
		return "", "", err
	}
	dir = filepath.Join(resolved, name)
	return dir, filepath.Join(dir, socketFile), nil
}

// socketPathFits refuses a base whose socket path would not fit a Unix
// socket address.
func socketPathFits(base string) error {
	if n := len(filepath.Join(base, socketDirPrefix)) + 2*socketDirRandom + len("/"+socketFile); n > MaxSocketPath {
		return fmt.Errorf("a socket path under %s would be %d bytes; Unix sockets take at most %d here, so set TMPDIR to a shorter directory", base, n, MaxSocketPath)
	}
	return nil
}

// startSocket starts a socket plugin in a new socket directory, waits for
// its socket, and connects with dial. On any failure the child is stopped
// and the directory removed.
func startSocket(ctx context.Context, spec child.Spec, base string,
	dial func(context.Context, string) (pluginmodel.Transport, error),
) (pluginmodel.Transport, error) {
	dir, sock, err := socketDir(base)
	if err != nil {
		return nil, err
	}
	spec.Env = []string{SocketEnv + "=" + sock}
	spec.SocketDir = dir
	p, err := child.Start(spec)
	if err != nil {
		_ = os.RemoveAll(dir)
		if errors.Is(err, child.ErrNotRecorded) {
			return nil, err
		}
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
	pluginmodel.Transport
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
