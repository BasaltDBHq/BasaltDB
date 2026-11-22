// Package peercred reads the OS user of the process on the other end of a
// Unix socket connection (owner decision #2: the engine identifies an agent
// by its socket plus the peer OS user). Linux uses SO_PEERCRED, macOS
// LOCAL_PEERCRED; other platforms are not supported.
package peercred

import (
	"errors"
	"net"
)

// ErrUnsupported is returned on platforms without a peer credential call.
var ErrUnsupported = errors.New("peer credentials are not supported on this platform")

// UID returns the effective uid of the peer of conn.
func UID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		uid, credErr = peerUID(int(fd))
	}); err != nil {
		return 0, err
	}
	return uid, credErr
}
