package app

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
)

// The shell's Connect hands the CLI a driver-free connection that runs
// queries on the connection it opened, carries that pgx connection for the
// guard's reads (pgquerier.Of) and closes it.
func TestShellConnectWrapsTheConnection(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx := context.Background()
	conn, err := shell{}.Connect(ctx, d.URL)
	require.NoError(t, err)
	raw, ok := pgquerier.Of(conn).(*pgx.Conn)
	require.True(t, ok, "the carried connection is the pgx connection pgdial opened")
	var one int
	require.NoError(t, conn.QueryRow(ctx, "SELECT 1").Scan(&one))
	require.Equal(t, 1, one)
	require.NoError(t, conn.Close(ctx))
	require.True(t, raw.IsClosed(), "Close closes the pgx connection")
}

// A connection the shell cannot open is a nil cli.Conn with the error, not
// a non-nil interface around nothing.
func TestShellConnectFailsWithANilConn(t *testing.T) {
	t.Parallel()
	conn, err := shell{}.Connect(context.Background(), "postgres://%zz")
	require.Error(t, err)
	require.True(t, conn == nil, "a failed Connect returns a nil interface")
}
