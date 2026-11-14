package guard

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// The session settings PinSession sets: Postgres's own defaults, in UTC.
const (
	PinnedTimeZone      = "UTC"
	PinnedDateStyle     = "ISO, MDY"
	PinnedIntervalStyle = "postgres"
)

// PinSession sets TimeZone, DateStyle and IntervalStyle for the current
// transaction only (set_config(..., true)), so nothing outlives it on a
// pooled connection. The guard's row images (to_jsonb in its triggers and
// in a revert's conflict check), the lines a person signs and their
// rowsHash, and the values a read returns then read the same whatever the
// client, role or database set: a timestamptz prints with +00:00, an
// interval as 01:30:00. Call it first in the transaction.
func PinSession(ctx context.Context, q Querier) error {
	return execCall(ctx, q, sq.Expr(
		"pg_catalog.set_config('TimeZone', ?, true), pg_catalog.set_config('DateStyle', ?, true), "+
			"pg_catalog.set_config('IntervalStyle', ?, true)",
		PinnedTimeZone, PinnedDateStyle, PinnedIntervalStyle))
}

// DB is a pgx pool or connection: queries, and transactions.
type DB interface {
	Querier
	TxBeginner
}

// PinnedDB is a DB whose every transaction starts with PinSession. A call
// made on it outside a transaction is not pinned: anything that builds row
// images or lines runs in a transaction begun on it.
type PinnedDB struct{ DB }

// Pinned wraps db; a db already pinned is returned as it is.
func Pinned(db DB) PinnedDB {
	if p, ok := db.(PinnedDB); ok {
		return p
	}
	return PinnedDB{DB: db}
}

// BeginTx begins a transaction and pins it.
func (p PinnedDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	return beginPinned(ctx, p.DB, opts)
}

// PinnedBeginner is a TxBeginner whose every transaction starts with
// PinSession.
type PinnedBeginner struct{ TxBeginner }

// BeginTx begins a transaction and pins it.
func (p PinnedBeginner) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	return beginPinned(ctx, p.TxBeginner, opts)
}

func beginPinned(ctx context.Context, db TxBeginner, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := PinSession(ctx, tx); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return tx, nil
}
