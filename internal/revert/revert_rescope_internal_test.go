package revert

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// A waiter for a revert's lock gives up when its context ends, and the
// lock is forgotten once nobody holds or waits for it.
func TestRevertLockWaiterHonorsItsContext(t *testing.T) {
	t.Parallel()
	r := newRescopes()
	id := uuid.New()
	release, err := r.lock(context.Background(), id)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.lock(ctx, id)
	require.ErrorIs(t, err, context.Canceled)

	other, err := r.lock(context.Background(), uuid.New())
	require.NoError(t, err, "another revert's lock is free")
	other()

	release()
	again, err := r.lock(context.Background(), id)
	require.NoError(t, err)
	again()
	require.Empty(t, r.locks)
}
