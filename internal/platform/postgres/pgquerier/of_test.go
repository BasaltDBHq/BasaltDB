package pgquerier_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
)

// carrier is a query port of another package over a driver connection.
type carrier struct{ q pgquerier.Querier }

func (c carrier) Pgx() pgquerier.Querier { return c.q }

// Of gives the driver connection of any port that carries one, Neutralize's
// included, and refuses a port that carries none.
func TestOfReadsTheCarriedConnection(t *testing.T) {
	t.Parallel()
	var conn pgquerier.Querier = struct{ pgquerier.Querier }{}
	require.Equal(t, conn, pgquerier.Of(pgquerier.Neutralize(conn)))
	require.Equal(t, conn, pgquerier.Of(carrier{conn}))
	require.Panics(t, func() { pgquerier.Of(struct{}{}) })
}

// closeCounter is a driver connection that counts its closes.
type closeCounter struct {
	pgquerier.Querier
	closed *int
}

func (c *closeCounter) Close(context.Context) error {
	*c.closed++
	return nil
}

// NeutralConn carries the connection it wraps (Of gives it back, the same
// one) and closes it.
func TestNeutralConnCarriesAndClosesTheConnection(t *testing.T) {
	t.Parallel()
	closed := 0
	conn := &closeCounter{closed: &closed}
	var c pgquerier.Closer = pgquerier.NeutralConn(conn)
	require.Same(t, conn, pgquerier.Of(c))
	require.NoError(t, c.Close(context.Background()))
	require.Equal(t, 1, closed)
}
