package dial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin/jsonrpc"
)

// ErrWrongPeer: the socket is not served by the entry's OS user, so the
// engine does not talk to it.
var ErrWrongPeer = connect.ErrWrongPeer

// errNotSocket: the path is missing, or is not itself a Unix socket.
var errNotSocket = errors.New("the plugin socket path is not a unix socket")

// Service reaches local entry k, verified as v, that its service unit runs
// as uid and that listens on sock (CONTRACT.md, Plugins, Service units). It
// starts no process. Every connection is checked before a byte is sent:
// sock is itself a socket, not a link to one, and the process listening on
// it runs as uid, so a socket another process put at the path, a hard link
// to one included, is refused. A jsonrpc-stdio entry is reached over its
// socket too: in service mode every local plugin listens on one.
func Service(ctx context.Context, k plugin.EntryKey, v plugin.Verified, sock string, uid uint32) (plugin.Transport, error) {
	l := v.Manifest.Endpoint.Local
	if l == nil {
		return nil, fmt.Errorf("plugin %s: a remote entry has no service unit", k)
	}
	check := PeerIs(uid)
	switch l.Transport {
	case TransportStdio, TransportUnix:
		nc, err := dialChecked(ctx, sock, check)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", k, err)
		}
		return jsonrpc.Open(nc), nil
	case TransportConnect:
		return wrap(k)(connect.DialLocalChecked(ctx, sock, check))
	}
	return nil, fmt.Errorf("plugin %s: transport %q is not served", k, l.Transport)
}

// PeerIs is a connection check: the peer's OS user is uid.
func PeerIs(uid uint32) func(net.Conn) error {
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return ErrWrongPeer
		}
		got, err := peercred.UID(uc)
		if err != nil || got != uid {
			return ErrWrongPeer
		}
		return nil
	}
}

// dialChecked connects to sock, refusing a path that is not itself a
// socket and a connection check refuses.
func dialChecked(ctx context.Context, sock string, check func(net.Conn) error) (net.Conn, error) {
	if fi, err := os.Lstat(sock); err != nil || fi.Mode().Type() != os.ModeSocket {
		return nil, errNotSocket
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, ErrNoSocket
	}
	if err := check(nc); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return nc, nil
}
