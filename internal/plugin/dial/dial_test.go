//go:build unix

package dial

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// A socket plugin that exits without listening is refused, and nothing is
// left at the socket path.
func TestSocketPluginThatNeverListens(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	v := plugin.Verified{Dir: "/", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	_, err = Entry(ctx, k, v, Options{SocketPath: sock})
	require.True(t, errors.Is(err, ErrNoSocket), "%v", err)
	require.Contains(t, err.Error(), "plugin acme-ner/default")
	_, err = os.Lstat(sock)
	require.True(t, os.IsNotExist(err))

	_, err = Entry(ctx, k, v, Options{SocketPath: "p.sock"})
	require.ErrorContains(t, err, "absolute socket path")
}
