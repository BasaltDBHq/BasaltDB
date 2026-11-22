package jsonrpc

import (
	"context"
	"fmt"
	"net"

	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// Dial connects to a plugin that is listening on the Unix socket at
// socketPath. The plugin owns the socket and the process behind it; Close
// ends this connection only. Every Dial is its own connection, so two
// instances of one plugin share nothing.
func Dial(ctx context.Context, socketPath string) (pluginhost.Transport, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("jsonrpc: connect to plugin socket: %w", err)
	}
	return newConn(nc, nc, func() { _ = nc.Close() }), nil
}

// Open is a transport over nc, a connection the caller made and checked
// (a service-mode engine checks the peer's OS user first). Close closes nc.
func Open(nc net.Conn) pluginhost.Transport {
	return newConn(nc, nc, func() { _ = nc.Close() })
}
