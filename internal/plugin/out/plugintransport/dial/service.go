package dial

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/peercred"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/jsonrpc"
)

// errNotSocket: the path is not itself a Unix socket.
var errNotSocket = errors.New("the plugin socket path is not a unix socket")

// ErrSocketDir: the socket directory is not the one the install made: a
// directory (not a link) owned by the entry's OS user, in the engine's
// group, with no access for others by its mode or an ACL entry.
var ErrSocketDir = errors.New("the plugin socket directory is not the plugin user's, in the engine's group and closed to others")

// socketDirACLError: the socket directory dir passes its owner, group and
// mode, but has an ACL entry that allows access (err nil) or an ACL that
// cannot be read (err). It is an ErrSocketDir, so status reads it as one.
type socketDirACLError struct {
	dir string
	err error
}

func (e socketDirACLError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("the plugin socket directory %s has an ACL that cannot be read (%v)", e.dir, e.err)
	}
	return fmt.Sprintf("the plugin socket directory %s has an ACL entry that opens it to others "+
		"(remove it: sudo setfacl -b %s on Linux, sudo chmod -N %s on macOS)", e.dir, e.dir, e.dir)
}

func (socketDirACLError) Is(target error) bool { return target == ErrSocketDir }

func (e socketDirACLError) Unwrap() error { return e.err }

// ErrSocketACL: the socket itself has an ACL entry that opens it to others,
// or an ACL that cannot be read.
var ErrSocketACL = errors.New("the plugin socket has an ACL entry that opens it to others, or an ACL that cannot be read")

// Service reaches local entry k, verified as v, that its service unit runs
// as uid and that listens on sock (CONTRACT.md, Plugins, Service units). It
// starts no process. Every connection, the first and each one the transport
// opens later, is checked before a byte is sent, by ConnCheck: the unit
// (recheck, which may be nil), sock's directory (owned by uid, in group gid,
// the engine's, closed to others), sock (no ACL entry opens it), and the
// process listening on sock, which
// must run as uid; sock itself must be a socket, not a link to one. Nothing
// at sock is ErrNoSocket. A jsonrpc-stdio entry is reached over its socket
// too: in service mode every local plugin listens on one.
func Service(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, sock string, uid, gid uint32, recheck func() error) (pluginmodel.Transport, error) {
	l := v.Manifest.Endpoint.Local
	if l == nil {
		return nil, fmt.Errorf("plugin %s: a remote entry has no service unit", k)
	}
	if err := checkSocketDir(filepath.Dir(sock), uid, gid); err != nil {
		return nil, fmt.Errorf("plugin %s: %w", k, err)
	}
	if _, err := os.Lstat(sock); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("plugin %s: %w", k, ErrNoSocket)
	}
	check := ConnCheck(sock, uid, gid, recheck)
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

// ConnCheck is the check Service runs on every connection to a service
// entry's socket sock: recheck (when not nil) passes, sock's directory is
// still owned by uid, in group gid and closed to others, no ACL entry opens
// sock, and the peer runs as uid.
func ConnCheck(sock string, uid, gid uint32, recheck func() error) func(net.Conn) error {
	peer := PeerIs(uid)
	dir := filepath.Dir(sock)
	return func(c net.Conn) error {
		if recheck != nil {
			if err := recheck(); err != nil {
				return err
			}
		}
		if err := checkSocketDir(dir, uid, gid); err != nil {
			return err
		}
		if openedByACL(sock) {
			return ErrSocketACL
		}
		return peer(c)
	}
}

// PeerIs is a connection check: the peer's OS user is uid.
func PeerIs(uid uint32) func(net.Conn) error {
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return connect.ErrWrongPeer
		}
		got, err := peercred.UID(uc)
		if err != nil || got != uid {
			return connect.ErrWrongPeer
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
