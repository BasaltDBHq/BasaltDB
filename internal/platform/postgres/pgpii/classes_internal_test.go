package pgpii

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
)

// fakeTx is a transaction a snapshot reads on.
type fakeTx struct {
	pgx.Tx
	rolledBack int
}

func (t *fakeTx) Rollback(context.Context) error { t.rolledBack++; return nil }

// fakePool opens its snapshots on tx, or fails to begin with beginErr.
type fakePool struct {
	Querier
	tx       *fakeTx
	beginErr error
	opts     []pgx.TxOptions
}

func (p *fakePool) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	p.opts = append(p.opts, opts)
	if p.beginErr != nil {
		return nil, p.beginErr
	}
	return p.tx, nil
}

// plainQuerier is a caller's transaction: it cannot open a snapshot.
type plainQuerier struct{ Querier }

// withSnapshot reads in a repeatable-read, read-only transaction of its own
// on the pool, rolled back after, and on the caller's transaction otherwise;
// it passes the read's error and the begin's error through.
func TestWithSnapshot(t *testing.T) {
	ctx := context.Background()
	on := func(_ context.Context, q Querier) (Querier, error) { return q, nil }

	tx := plainQuerier{}
	got, err := withSnapshot(ctx, ClassesInTx(tx), on)
	require.NoError(t, err)
	require.Equal(t, Querier(tx), got, "inside a transaction it reads there")

	snap := &fakeTx{}
	pool := &fakePool{tx: snap}
	got, err = withSnapshot(ctx, Classes(pool), on)
	require.NoError(t, err)
	require.Equal(t, Querier(snap), got, "a pool reads in its snapshot")
	require.Equal(t, []pgx.TxOptions{{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}}, pool.opts)
	require.Equal(t, 1, snap.rolledBack)

	readErr := errors.New("read failed")
	_, err = withSnapshot(ctx, Classes(pool), func(context.Context, Querier) (int, error) { return 0, readErr })
	require.ErrorIs(t, err, readErr)
	require.Equal(t, 2, snap.rolledBack)

	beginErr := errors.New("cannot begin")
	_, err = withSnapshot(ctx, Classes(&fakePool{beginErr: beginErr}), on)
	require.ErrorIs(t, err, beginErr)
}

// A pool's loads are shared; a transaction's are not. A field's resource is
// its table's oid.
func TestSharedAndResourceOf(t *testing.T) {
	require.True(t, Classes(&fakePool{}).Shared())
	require.False(t, ClassesInTx(plainQuerier{}).Shared())
	require.Equal(t, agentstore.ResourceRef("16384"), ClassesInTx(plainQuerier{}).ResourceOf("16384/3"))
}
