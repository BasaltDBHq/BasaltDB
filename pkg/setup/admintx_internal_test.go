package setup

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// A commit asked for with a context already done is never sent: a known
// failure, not SETUP_UNCONFIRMED, and the transaction rolls back.
func TestAdminTxCommitNeverSent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := adminTx(d.Admin)(ctx, func(q setuprun.Querier) error {
		if _, err := q.Exec(ctx, `CREATE TABLE public.never_committed (id int)`); err != nil {
			return err
		}
		cancel()
		return nil
	})
	require.Error(t, err)
	var u *setuprun.UnconfirmedError
	require.False(t, errors.As(err, &u), "a commit never sent is a known failure: %v", err)
	var exists bool
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT to_regclass('public.never_committed') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "the transaction rolled back")
}
