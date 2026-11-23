package pii

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// plainHandle is a handle that cannot open a snapshot (a transaction).
type plainHandle struct{ PiidictQuerier }

// poolHandle opens its snapshots on tx, or fails to begin with beginErr.
type poolHandle struct {
	PiidictQuerier
	tx       PiidictQuerier
	beginErr error
	opened   int
}

func (p *poolHandle) ReadOnlySnapshot() (func(ctx context.Context, fn func(PiidictQuerier) error) error, bool) {
	return func(_ context.Context, fn func(PiidictQuerier) error) error {
		if p.beginErr != nil {
			return p.beginErr
		}
		p.opened++
		return fn(p.tx)
	}, true
}

// withSnapshot reads in a snapshot of its own on a handle that can open
// one, and on the handle itself otherwise; it passes the read's error and
// the begin's error through.
func TestWithSnapshot(t *testing.T) {
	ctx := context.Background()
	on := func(_ context.Context, q PiidictQuerier) (PiidictQuerier, error) { return q, nil }

	tx := plainHandle{}
	got, err := withSnapshot(ctx, tx, on)
	require.NoError(t, err)
	require.Equal(t, PiidictQuerier(tx), got, "inside a transaction it reads there")

	snap := plainHandle{}
	pool := &poolHandle{tx: snap}
	got, err = withSnapshot(ctx, pool, on)
	require.NoError(t, err)
	require.Equal(t, PiidictQuerier(snap), got, "a pool reads in its snapshot")
	require.Equal(t, 1, pool.opened)

	readErr := errors.New("read failed")
	_, err = withSnapshot(ctx, pool, func(context.Context, PiidictQuerier) (int, error) { return 0, readErr })
	require.ErrorIs(t, err, readErr)

	beginErr := errors.New("cannot begin")
	_, err = withSnapshot(ctx, &poolHandle{beginErr: beginErr}, on)
	require.ErrorIs(t, err, beginErr)

	_, ok := snapshotOf(tx)
	require.False(t, ok)
	_, ok = snapshotOf(pool)
	require.True(t, ok)
}

// beginsTx is a pool or connection: it can begin a transaction.
type beginsTx struct{ pgquerier.Querier }

func (beginsTx) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}

// txHandle is a transaction: it cannot.
type txHandle struct{ pgquerier.Querier }

// The handles pii is given, wrapped by pgquerier.Neutralize, open their own
// snapshot when they wrap a pool or a connection, and not when they wrap a
// transaction.
func TestSnapshotOfWrappedHandles(t *testing.T) {
	_, ok := snapshotOf(pgquerier.Neutralize(beginsTx{}))
	require.True(t, ok)
	_, ok = snapshotOf(pgquerier.Neutralize(txHandle{}))
	require.False(t, ok)
}
