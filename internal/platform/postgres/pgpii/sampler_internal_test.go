package pgpii

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// A sample that fails with a Postgres error keeps only its SQLSTATE; any
// other error is a failed connection.
func TestSampleErrors(t *testing.T) {
	col := piistore.Column{Namespace: "public", Resource: "people", Name: "email", Kind: piistore.KindText}
	failing := func(err error) Sampler {
		return Sampler{ReadOnly: func(context.Context, func(sqlport.Port) error) error { return err }}
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{&pgconn.PgError{Code: sqlStateQueryCanceled, Message: "canceling statement"}, piistore.UnavailableTimeout},
		{&pgconn.PgError{Code: sqlStatePermissionDenied}, piistore.UnavailableNoReadable},
		{&pgconn.PgError{Code: "22P02", Message: `invalid input syntax: "ann@example.com"`}, "error 22P02"},
	} {
		s, err := failing(c.err).Sample(context.Background(), col)
		require.NoError(t, err)
		require.Equal(t, piistore.Sample{Unavailable: c.want}, s)
	}
	_, err := failing(errors.New("conn closed")).Sample(context.Background(), col)
	require.EqualError(t, err, "sample public.people.email: the connection failed")
}
