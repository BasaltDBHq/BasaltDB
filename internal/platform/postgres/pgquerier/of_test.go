package pgquerier_test

import (
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
