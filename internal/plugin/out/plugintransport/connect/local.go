package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// ErrNotSocket: the path is missing or is not a Unix socket (a symbolic link
// to one is refused too).
var ErrNotSocket = errors.New("the plugin socket path is not a unix socket")

// DialLocal connects to a local plugin that serves ConnectRPC or gRPC on the
// Unix socket at socketPath, and returns a transport for it. The calls are
// HTTP/2 without TLS (prior knowledge); the socket's ownership and mode are
// the protection, as for the JSON-RPC socket. Methods, size caps and failure
// classes are the remote path's.
//
// The transport reaches the socket and nothing else: whatever address a
// request names, the dial is to socketPath; there is no proxy, no redirect,
// no Authorization header and no credential file. A refusal names the
// socket's file name only and wraps ErrNotSocket, ErrUnreachable or ctx's
// error.
func DialLocal(ctx context.Context, socketPath string) (pluginmodel.Transport, error) {
	return dialLocal(ctx, socketPath, options{})
}

// DialLocalChecked is DialLocal with check run on every new connection
// before it is used: a connection check refuses is closed, and the call
// fails ErrWrongPeer. A service-mode engine checks the peer's OS user.
func DialLocalChecked(ctx context.Context, socketPath string, check func(net.Conn) error) (pluginmodel.Transport, error) {
	return dialLocal(ctx, socketPath, options{check: check})
}

// ErrWrongPeer: the process listening on the socket is not the one the
// entry's unit runs.
var ErrWrongPeer = errors.New("the plugin socket is served by another process than the plugin's")

func dialLocal(ctx context.Context, socketPath string, opts options) (pluginmodel.Transport, error) {
	name := filepath.Base(socketPath)
	if !isSocket(socketPath) {
		return nil, localError(name, ErrNotSocket)
	}

	dialer := &net.Dialer{Timeout: connectTimeout}
	// The HTTP transport opens new connections on its own; each one checks
	// again that the path is still a socket, not a link put in its place.
	dialSocket := func(ctx context.Context) (net.Conn, error) {
		if !isSocket(socketPath) {
			return nil, localError(name, ErrNotSocket)
		}
		c, err := dialer.DialContext(ctx, "unix", socketPath)
		if err != nil || opts.check == nil {
			return c, err
		}
		if err := opts.check(c); err != nil {
			_ = c.Close()
			return nil, localError(name, ErrWrongPeer)
		}
		return c, nil
	}
	// Connect once, so a dead socket is refused here and not at the first call.
	c, err := dialSocket(ctx)
	if errors.Is(err, ErrWrongPeer) || errors.Is(err, ErrNotSocket) {
		return nil, err
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, localError(name, ctxErr)
		}
		return nil, localError(name, ErrUnreachable)
	}
	_ = c.Close()

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true) // h2c with prior knowledge, no HTTP/1
	tr := &http.Transport{
		Proxy: nil,
		// The address in the request is ignored: this is the only place the
		// transport can connect to.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialSocket(ctx)
		},
		Protocols:              &protocols,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxResponseHeader,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		IdleConnTimeout:        idleConnTimeout,
	}
	// The host name is a placeholder: it is only the :authority the plugin sees.
	return newConn(tr, "http://localhost", func(http.Header) {}, opts), nil
}

// isSocket reports whether path itself, not followed, is a Unix socket.
func isSocket(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().Type() == os.ModeSocket
}

func localError(name string, reason error) error {
	return fmt.Errorf("connect: socket %s: %w", name, reason)
}
