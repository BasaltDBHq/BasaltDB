package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
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
func DialLocal(ctx context.Context, socketPath string) (plugin.Transport, error) {
	return dialLocal(ctx, socketPath, options{})
}

func dialLocal(ctx context.Context, socketPath string, opts options) (plugin.Transport, error) {
	name := filepath.Base(socketPath)
	fi, err := os.Lstat(socketPath)
	if err != nil || fi.Mode().Type() != os.ModeSocket {
		return nil, localError(name, ErrNotSocket)
	}

	dialer := &net.Dialer{Timeout: connectTimeout}
	dialSocket := func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socketPath)
	}
	// Connect once, so a dead socket is refused here and not at the first call.
	c, err := dialSocket(ctx)
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

func localError(name string, reason error) error {
	return fmt.Errorf("connect: socket %s: %w", name, reason)
}
