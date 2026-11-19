//go:build unix

package dial

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/child"
)

// A socket plugin that exits without listening is refused, and its socket
// directory is gone.
func TestSocketPluginThatNeverListens(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	v := plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	_, err := Entry(ctx, k, v, Options{SocketBase: base})
	require.True(t, errors.Is(err, ErrNoSocket), "%v", err)
	require.Contains(t, err.Error(), "plugin acme-ner/default")
	left, err := os.ReadDir(base)
	require.NoError(t, err)
	require.Empty(t, left)
}

// A socket base too long for a Unix socket path is refused before anything
// starts, with the rule.
func TestSocketPathTooLong(t *testing.T) {
	t.Parallel()
	base := filepath.Join(shortBase(t), strings.Repeat("d", MaxSocketPath))
	v := plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: TransportConnect, Command: "usr/bin/true"}}}}
	_, err := Entry(context.Background(), plugin.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base})
	require.ErrorContains(t, err, "Unix sockets take at most")
}

// A socket base that group or others can write, sticky or not, is refused
// before anything starts or is made, with the fix.
func TestSocketBaseOthersCanWriteIsRefused(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o777, 0o770, 0o1777} {
		base := shortBase(t)
		require.NoError(t, os.Chmod(base, mode))
		v := plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
		_, err := Entry(context.Background(), plugin.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base})
		require.ErrorContains(t, err, plugin.WhyGroupWritable, "mode %o", mode)
		require.ErrorContains(t, err, "set TMPDIR")
		left, err := os.ReadDir(base)
		require.NoError(t, err)
		require.Empty(t, left, "mode %o: nothing made", mode)
	}
}

// With Runs set, a socket plugin's start is recorded with its socket
// directory until it is closed.
func TestSocketPluginIsRecorded(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	runs := filepath.Join(shortBase(t), "runs")
	v := plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// It never listens, so the start fails after the process was recorded;
	// the failed start stops it and drops the record.
	_, err := Entry(ctx, plugin.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base, Runs: &child.Runs{Dir: runs}})
	require.ErrorIs(t, err, ErrNoSocket)
	recs, err := os.ReadDir(runs)
	require.NoError(t, err, "the start was recorded")
	require.Empty(t, recs, "and the record dropped when it stopped")
}

// shortBase is a new directory short enough for socket paths (t.TempDir is
// too long on macOS).
func shortBase(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
