package setup_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// Only a commit the database may have applied without answering is
// unconfirmed: an answered error, a commit turned into a rollback and a
// commit the driver never sent are known failures. Run then refuses
// SETUP_UNCONFIRMED, and never says that nothing changed.
func TestCommitWithNoAnswerIsUnconfirmed(t *testing.T) {
	t.Parallel()
	commit := func(err error) error {
		be := &commitsWith{Store: setupstore.New(), err: err}
		got := setup.AdminTx(be, nil)(context.Background(), func(setup.Querier) error { return nil })
		require.True(t, be.rolledBack, "the closing rollback runs, a no-op after a commit")
		return got
	}
	require.NoError(t, commit(nil))
	answered := &pgconn.PgError{Code: "40001"}
	require.Same(t, error(answered), commit(answered))
	require.ErrorIs(t, commit(pgx.ErrTxCommitRollback), pgx.ErrTxCommitRollback)
	var u *setup.UnconfirmedError
	never := commit(fmt.Errorf("commit: %w", neverSentError{}))
	require.ErrorIs(t, never, neverSentError{})
	require.False(t, errors.As(never, &u), "a commit never sent is a known failure")
	lost := commit(io.ErrUnexpectedEOF)
	require.True(t, errors.As(lost, &u))
	require.ErrorIs(t, lost, io.ErrUnexpectedEOF)

	var r *setup.SetuprunRefusalError
	require.True(t, errors.As(setup.Refused(context.Background(), setupstore.New(), nil, setupcode.Payload{}, lost), &r))
	require.Equal(t, setup.SetuprunCodeSetupUnconfirmed, r.Code)
	require.Equal(t, "the database did not confirm the setup, so it may or may not have run. Check the setup again to see which", r.Message)
	require.NotContains(t, r.Message, "othing changed")
}

// commitsWith is the setup store with a transaction whose commit fails
// with err.
type commitsWith struct {
	setupstore.Store
	err        error
	rolledBack bool
}

func (*commitsWith) BeginTx(context.Context, setup.Querier) (setup.Querier, error) {
	return struct{ setup.Querier }{}, nil
}
func (c *commitsWith) CommitTx(context.Context, setup.Querier) error { return c.err }
func (c *commitsWith) RollbackTx(context.Context, setup.Querier) error {
	c.rolledBack = true
	return nil
}

// neverSentError is a driver error for a statement it never sent.
type neverSentError struct{}

func (neverSentError) Error() string     { return "never sent" }
func (neverSentError) SafeToRetry() bool { return true }
