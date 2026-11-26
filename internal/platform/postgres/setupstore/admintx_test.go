package setupstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// A commit asked for with a context already done is never sent: a known
// failure, not SETUP_UNCONFIRMED, and the transaction rolls back.
func TestAdminTxCommitNeverSent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := setup.AdminTx(setupstore.New(), setupstore.Port(d.Admin))(ctx, func(q setup.Querier) error {
		if _, err := q.Exec(ctx, `CREATE TABLE public.never_committed (id int)`); err != nil {
			return err
		}
		cancel()
		return nil
	})
	require.Error(t, err)
	var u *setup.UnconfirmedError
	require.False(t, errors.As(err, &u), "a commit never sent is a known failure: %v", err)
	// The driver closes a connection whose commit it never sent, the
	// session still in a transaction: read on a new one.
	fresh, err := pgdial.Connect(context.Background(), d.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fresh.Close(context.Background()) })
	var exists bool
	require.NoError(t, fresh.QueryRow(context.Background(), `SELECT to_regclass('public.never_committed') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "the transaction rolled back")
}
