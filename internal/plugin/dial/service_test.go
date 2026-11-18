//go:build unix

package dial

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// listenUnix serves sock and counts the connections it accepts.
func listenUnix(t *testing.T, sock string) *atomic.Int32 {
	t.Helper()
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return &n
}

func serviceEntry(transport string) plugin.Verified {
	return plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: transport, Command: "bin/p"}}}}
}

// In service mode the engine connects to the unit's socket, starts no
// process, and talks only to the entry's OS user.
func TestServiceConnectsOnlyToTheEntrysUser(t *testing.T) {
	t.Parallel()
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	for _, transport := range []string{TransportStdio, TransportUnix, TransportConnect} {
		sock := filepath.Join(shortBase(t), "p.sock")
		accepted := listenUnix(t, sock)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		tr, err := Service(ctx, k, serviceEntry(transport), sock, me)
		require.NoError(t, err, transport)
		require.NoError(t, tr.Close())
		require.Eventually(t, func() bool { return accepted.Load() >= 1 }, 2*time.Second, 10*time.Millisecond)

		_, err = Service(ctx, k, serviceEntry(transport), sock, me+1)
		require.Error(t, err, transport)
		require.True(t, errors.Is(err, ErrWrongPeer), "%s: %v", transport, err)
		require.Contains(t, err.Error(), "plugin acme-ner/default")
		cancel()
	}
}

// A link at the socket's path, or nothing there, is refused before any
// connection, whoever serves its target.
func TestServiceRefusesALinkOrNoSocket(t *testing.T) {
	t.Parallel()
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	dir := shortBase(t)
	target := filepath.Join(dir, "real.sock")
	accepted := listenUnix(t, target)
	link := filepath.Join(dir, "p.sock")
	require.NoError(t, os.Symlink(target, link))
	for _, transport := range []string{TransportUnix, TransportConnect} {
		_, err := Service(context.Background(), k, serviceEntry(transport), link, me)
		require.Error(t, err, transport)
	}
	require.Zero(t, accepted.Load(), "the link's target was never reached")

	_, err := Service(context.Background(), k, serviceEntry(TransportUnix), filepath.Join(dir, "missing.sock"), me)
	require.Error(t, err)

	remote := plugin.Verified{Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: TransportConnect, URL: "https://x.example"}}}}
	_, err = Service(context.Background(), k, remote, link, me)
	require.Error(t, err)
}
