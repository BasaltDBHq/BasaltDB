package pii

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// quoteIdentifier writes what the driver's Identifier.Sanitize writes.
func TestQuoteIdentifier(t *testing.T) {
	for _, parts := range [][]string{
		{"email"}, {"public", "people"}, {`we"ird`, "Mixed Case"}, {"nul\x00byte"}, {""},
	} {
		require.Equal(t, pgx.Identifier(parts).Sanitize(), quoteIdentifier(parts...), "%q", parts)
	}
}

// A sample that fails with a Postgres error keeps only its SQLSTATE; any
// other error is a failed connection.
func TestSampleErrors(t *testing.T) {
	col := Column{Schema: "public", Table: "people", Name: "email"}
	failing := func(err error) Sampler {
		return Sampler{ReadOnly: func(context.Context, func(Querier) error) error { return err }}
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{&pgconn.PgError{Code: sqlStateQueryCanceled, Message: "canceling statement"}, UnavailableTimeout},
		{&pgconn.PgError{Code: sqlStatePermissionDenied}, UnavailableNoReadable},
		{&pgconn.PgError{Code: "22P02", Message: `invalid input syntax: "ann@example.com"`}, "error 22P02"},
	} {
		s, err := failing(c.err).Sample(context.Background(), col)
		require.NoError(t, err)
		require.Equal(t, Sample{Unavailable: c.want}, s)
	}
	_, err := failing(errors.New("conn closed")).Sample(context.Background(), col)
	require.EqualError(t, err, "sample public.people.email: the connection failed")
}
