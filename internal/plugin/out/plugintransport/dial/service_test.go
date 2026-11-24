//go:build unix

package dial

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/connect"
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

func serviceEntry(transport string) pluginmodel.Verified {
	return pluginmodel.Verified{Dir: "/", Manifest: pluginmodel.Manifest{Endpoint: pluginmodel.Endpoint{Local: &pluginmodel.LocalEndpoint{Transport: transport, Command: "bin/p"}}}}
}

// In service mode the engine connects to the unit's socket, starts no
// process, and talks only to the entry's OS user.
func TestServiceConnectsOnlyToTheEntrysUser(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	for _, transport := range []string{TransportStdio, TransportUnix, TransportConnect} {
		dir := shortBase(t)
		sock := filepath.Join(dir, "p.sock")
		accepted := listenUnix(t, sock)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		gid := dirGID(t, dir)

		tr, err := Service(ctx, k, serviceEntry(transport), sock, me, gid, nil)
		require.NoError(t, err, transport)
		require.NoError(t, tr.Close())
		require.Eventually(t, func() bool { return accepted.Load() >= 1 }, 2*time.Second, 10*time.Millisecond)

		// Another uid: its socket directory is not that user's.
		_, err = Service(ctx, k, serviceEntry(transport), sock, me+1, gid, nil)
		require.Error(t, err, transport)
		require.True(t, errors.Is(err, ErrSocketDir), "%s: %v", transport, err)
		require.Contains(t, err.Error(), "plugin acme-ner/default")

		// The peer check refuses a listener under another uid.
		if transport == TransportConnect {
			_, err = connect.DialLocalChecked(ctx, sock, PeerIs(me+1))
		} else {
			_, err = dialChecked(ctx, sock, PeerIs(me+1))
		}
		require.True(t, errors.Is(err, connect.ErrWrongPeer), "%s: %v", transport, err)
		cancel()
	}
}

// A link at the socket's path, or nothing there, is refused before any
// connection, whoever serves its target.
func TestServiceRefusesALinkOrNoSocket(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	dir := shortBase(t)
	gid := dirGID(t, dir)
	target := filepath.Join(dir, "real.sock")
	accepted := listenUnix(t, target)
	link := filepath.Join(dir, "p.sock")
	require.NoError(t, os.Symlink(target, link))
	for _, transport := range []string{TransportUnix, TransportConnect} {
		_, err := Service(context.Background(), k, serviceEntry(transport), link, me, gid, nil)
		require.Error(t, err, transport)
	}
	require.Zero(t, accepted.Load(), "the link's target was never reached")

	_, err := Service(context.Background(), k, serviceEntry(TransportUnix), filepath.Join(dir, "missing.sock"), me, gid, nil)
	require.ErrorIs(t, err, ErrNoSocket, "nothing listens: the plugin never made its socket")

	remote := pluginmodel.Verified{Manifest: pluginmodel.Manifest{Endpoint: pluginmodel.Endpoint{Remote: &pluginmodel.RemoteEndpoint{Transport: TransportConnect, URL: "https://x.example"}}}}
	_, err = Service(context.Background(), k, remote, link, me, gid, nil)
	require.Error(t, err)
}

// The socket directory is checked at each connection: one opened to others,
// in another group, or a link to a directory is refused before the socket
// is reached.
func TestServiceChecksTheSocketDirectoryEachTime(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	dir := shortBase(t)
	gid := dirGID(t, dir)
	sock := filepath.Join(dir, "p.sock")
	accepted := listenUnix(t, sock)
	dialOnce := func(sock string, gid uint32) error {
		tr, err := Service(context.Background(), k, serviceEntry(TransportUnix), sock, me, gid, nil)
		if err == nil {
			_ = tr.Close()
		}
		return err
	}
	require.NoError(t, os.Chmod(dir, 0o750))
	require.NoError(t, dialOnce(sock, gid))

	require.NoError(t, os.Chmod(dir, 0o751))
	require.ErrorIs(t, dialOnce(sock, gid), ErrSocketDir, "others may enter")
	require.NoError(t, os.Chmod(dir, 0o750))
	require.ErrorIs(t, dialOnce(sock, gid+1), ErrSocketDir, "not the engine's group")

	link := filepath.Join(shortBase(t), "d")
	require.NoError(t, os.Symlink(dir, link))
	require.ErrorIs(t, dialOnce(filepath.Join(link, "p.sock"), gid), ErrSocketDir, "a link to the directory")

	require.NoError(t, dialOnce(sock, gid), "closed again: connected")
	require.Eventually(t, func() bool { return accepted.Load() == 2 }, 2*time.Second, 10*time.Millisecond)
}

// dirGID is dir's group: on macOS a new directory takes its parent's.
func dirGID(t *testing.T, dir string) uint32 {
	t.Helper()
	fi, err := os.Stat(dir)
	require.NoError(t, err)
	return fi.Sys().(*syscall.Stat_t).Gid
}

// The unit recheck and the directory check run on the connection itself,
// for every transport: a connect transport's later connections go through
// the same check, so a unit or directory changed after the first one is
// refused there too.
func TestServiceChecksEveryConnectionOfEveryTransport(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	me := uint32(os.Getuid())
	for _, transport := range []string{TransportStdio, TransportUnix, TransportConnect} {
		dir := shortBase(t)
		gid := dirGID(t, dir)
		sock := filepath.Join(dir, "p.sock")
		listenUnix(t, sock)
		var calls atomic.Int32
		tr, err := Service(context.Background(), k, serviceEntry(transport), sock, me, gid, func() error {
			calls.Add(1)
			return nil
		})
		require.NoError(t, err, transport)
		require.NoError(t, tr.Close())
		require.Positive(t, calls.Load(), "%s: the recheck ran on the connection", transport)

		changed := errors.New("unit changed")
		_, err = Service(context.Background(), k, serviceEntry(transport), sock, me, gid, func() error { return changed })
		require.Error(t, err, transport)
	}

	// The check itself: recheck, then the directory, then the peer.
	dir := shortBase(t)
	gid := dirGID(t, dir)
	sock := filepath.Join(dir, "p.sock")
	listenUnix(t, sock)
	c, err := net.Dial("unix", sock)
	require.NoError(t, err)
	defer c.Close()
	changed := errors.New("unit changed")
	require.NoError(t, ConnCheck(sock, me, gid, nil)(c))
	require.ErrorIs(t, ConnCheck(sock, me, gid, func() error { return changed })(c), changed)
	require.NoError(t, os.Chmod(dir, 0o755))
	require.ErrorIs(t, ConnCheck(sock, me, gid, nil)(c), ErrSocketDir, "opened to others after the first connection")
	require.NoError(t, os.Chmod(dir, 0o700))
	require.ErrorIs(t, ConnCheck(sock, me, gid+1, nil)(c), ErrSocketDir)
}
