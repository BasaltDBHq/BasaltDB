//go:build linux || darwin

package peercred_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
)

func TestUIDIsThePeersUser(t *testing.T) {
	t.Parallel()
	// Short dir: Unix socket paths are limited to about 104 bytes on macOS.
	dir, err := os.MkdirTemp("", "bpc")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		c, err := net.Dial("unix", path)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Read(make([]byte, 1))
	}()
	conn, err := ln.AcceptUnix()
	require.NoError(t, err)
	defer conn.Close()

	uid, err := peercred.UID(conn)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getuid()), uid)
}
