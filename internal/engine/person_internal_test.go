//go:build linux || darwin

package engine

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

func TestListenPersonOpensTheSocketLikeTheAgentSockets(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bep") // short: Unix socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := config.Config{SocketDir: filepath.Join(dir, "run"), Mode: config.ModeService, PersonUIDs: []uint32{4242}}

	srv, ln, err := listenPerson(cfg, map[string]person.Ledger{}, map[string]uint32{}, person.PagesDTO{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	path := filepath.Join(dir, "run", "person.sock")
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(socketMode), fi.Mode().Perm(), "0666: the peer uid allowlist is the access control")
	di, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(socketDirMode), di.Mode().Perm())

	// This process is the engine: its own uid is refused although nothing
	// else is recorded.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	_, err = person.Client{Path: path}.Pages(ctx)
	require.True(t, errors.Is(err, person.ErrUIDNotAllowed), "%v", err)
	cancel()
	<-done
	_, err = os.Stat(path)
	require.True(t, errors.Is(err, os.ErrNotExist), "the socket goes when the engine stops")
}
