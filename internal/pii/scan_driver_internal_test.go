package pii

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

// The scan's json type OIDs are the driver's.
func TestScanJSONOIDs(t *testing.T) {
	require.Equal(t, uint32(pgtype.JSONOID), uint32(jsonOID))
	require.Equal(t, uint32(pgtype.JSONBOID), uint32(jsonbOID))
}

// A relation gone, or no longer readable, skips it; a slow one-pass read
// skips it; anything else fails the cycle. A gone relation reads as the
// undefined_table Postgres raises.
func TestSkipReason(t *testing.T) {
	gone := relationGoneError{}
	require.Equal(t, (&pgconn.PgError{Code: sqlStateUndefinedTable, Message: "table is gone"}).Error(), gone.Error())
	for _, err := range []error{
		gone,
		fmt.Errorf("wrapped: %w", gone),
		&pgconn.PgError{Code: sqlStateUndefinedTable},
		&pgconn.PgError{Code: sqlStateUndefinedColumn},
		&pgconn.PgError{Code: sqlStateInsufficient},
	} {
		require.Equal(t, "the agent can no longer read it", skipReason(err), "%v", err)
	}
	require.NotEmpty(t, skipReason(&slowRelationError{err: &pgconn.PgError{Code: piidictSqlStateQueryCanceled}}))
	require.Empty(t, skipReason(&pgconn.PgError{Code: piidictSqlStateQueryCanceled}))
	require.Empty(t, skipReason(errors.New("conn closed")))
	require.Empty(t, skipReason(nil))
}

// keysetOf reads a relation that is gone as relationGoneError.
func TestKeysetOfAGoneRelation(t *testing.T) {
	_, _, err := keysetOf(context.Background(), noRows{}, 42)
	require.ErrorIs(t, err, relationGoneError{})
}

// noRows answers every query with no rows.
type noRows struct{ PiidictQuerier }

func (noRows) Query(context.Context, string, ...any) (Rows, error) { return emptyRows{}, nil }

type emptyRows struct{}

func (emptyRows) Close()            {}
func (emptyRows) Err() error        { return nil }
func (emptyRows) Next() bool        { return false }
func (emptyRows) Scan(...any) error { return nil }
