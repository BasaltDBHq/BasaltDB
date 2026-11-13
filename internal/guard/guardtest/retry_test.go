package guardtest

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestRetryDeadlock(t *testing.T) {
	t.Parallel()
	deadlock := &pgconn.PgError{Code: "40P01"}
	other := errors.New("boom")

	t.Run("retries a deadlock until it passes", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryDeadlock(func() error {
			calls++
			if calls < 3 {
				return deadlock
			}
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, 3, calls)
	})
	t.Run("gives up on a deadlock that persists", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryDeadlock(func() error { calls++; return deadlock })
		require.Equal(t, "40P01", SQLState(err))
		require.Equal(t, deadlockAttempts, calls)
	})
	t.Run("does not retry other errors", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryDeadlock(func() error { calls++; return other })
		require.ErrorIs(t, err, other)
		require.Equal(t, 1, calls)
	})
}
