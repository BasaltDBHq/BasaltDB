package engineos

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// socketDirMode lets agents' OS users reach their sockets.
	socketDirMode = 0o755
	// socketMode lets any local user connect; the peer uid check on accept
	// is what authorizes a connection.
	socketMode = 0o666
)

// ListenSocket listens on path, replacing a stale socket file but never any
// other kind of file, and opens the socket to local users.
func (OS) ListenSocket(path string) (*net.UnixListener, error) {
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

// TemporaryAccept reports an accept error that passes: out of file
// descriptors or memory, or a connection aborted before it was taken.
func (OS) TemporaryAccept(err error) bool {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED, syscall.EINTR} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
