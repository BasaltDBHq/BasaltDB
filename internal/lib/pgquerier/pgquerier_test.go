package pgquerier_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// txOnly is a handle with no BeginTx, as a transaction is.
type txOnly struct{ pgquerier.Querier }

// fakeTx is a transaction that only records its rollback.
type fakeTx struct {
	pgx.Tx
	rolledBack bool
}

func (t *fakeTx) Rollback(context.Context) error { t.rolledBack = true; return nil }

// fakePool begins fakeTx with the options it is given.
type fakePool struct {
	pgquerier.Querier
	opts pgx.TxOptions
	tx   *fakeTx
}

func (p *fakePool) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	p.opts = opts
	return p.tx, nil
}

// A handle that cannot begin a transaction of its own has no snapshots.
func TestReadOnlySnapshotOfATransaction(t *testing.T) {
	run, ok := pgquerier.Neutralize(txOnly{}).ReadOnlySnapshot()
	require.False(t, ok)
	require.Nil(t, run)
}

// A pool's snapshot is a repeatable-read, read-only transaction, read
// through a wrapped handle and rolled back after, whatever the read
// returns.
func TestReadOnlySnapshotOfAPool(t *testing.T) {
	pool := &fakePool{tx: &fakeTx{}}
	run, ok := pgquerier.Neutralize(pool).ReadOnlySnapshot()
	require.True(t, ok)
	readErr := errors.New("read failed")
	err := run(context.Background(), func(q pgquerier.Port) error {
		require.Equal(t, pgx.Tx(pool.tx), pgquerier.Unwrap(q))
		return readErr
	})
	require.ErrorIs(t, err, readErr)
	require.Equal(t, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, pool.opts)
	require.True(t, pool.tx.rolledBack)
}
