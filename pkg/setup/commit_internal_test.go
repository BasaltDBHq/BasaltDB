package setup

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// Only a commit the database did not answer is unconfirmed: an answered
// error and a commit turned into a rollback are known failures. Run then
// refuses SETUP_UNCONFIRMED, and never says that nothing changed.
func TestCommitWithNoAnswerIsUnconfirmed(t *testing.T) {
	t.Parallel()
	require.NoError(t, commitOutcome(nil))
	answered := &pgconn.PgError{Code: "40001"}
	require.Same(t, error(answered), commitOutcome(answered))
	require.ErrorIs(t, commitOutcome(pgx.ErrTxCommitRollback), pgx.ErrTxCommitRollback)
	var u *setuprun.UnconfirmedError
	lost := commitOutcome(io.ErrUnexpectedEOF)
	require.True(t, errors.As(lost, &u))
	require.ErrorIs(t, lost, io.ErrUnexpectedEOF)

	err := asError(setuprun.Refused(context.Background(), store, nil, setupcode.Payload{}, lost))
	var e *Error
	require.True(t, errors.As(err, &e))
	require.Equal(t, CodeSetupUnconfirmed, e.Code)
	require.Equal(t, "the database did not confirm the setup, so it may or may not have run. Check the setup again to see which", e.Message)
	require.NotContains(t, e.Message, "othing changed")
	require.Contains(t, Codes(), CodeSetupUnconfirmed)
}
