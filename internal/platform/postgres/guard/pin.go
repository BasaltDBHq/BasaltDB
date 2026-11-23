package guard

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// The session settings PinSession sets: Postgres's own defaults, in UTC,
// and the C locale's money format. The guard's row trigger and the
// revert's row read and restore set the same values for themselves
// (basalt_meta versions 34 and 35), and a test keeps them equal
// (TestGuardPinsTheSessionSettings).
const (
	PinnedTimeZone         = "UTC"
	PinnedDateStyle        = "ISO, MDY"
	PinnedIntervalStyle    = "postgres"
	PinnedExtraFloatDigits = "1"
	PinnedLcMonetary       = "C"
	PinnedByteaOutput      = "hex"
)

// PinSession sets TimeZone, DateStyle, IntervalStyle, extra_float_digits,
// lc_monetary and bytea_output for the current transaction only
// (set_config(..., true)), so nothing outlives it on a pooled connection.
// The guard's row images (to_jsonb in its triggers and in a revert's
// conflict check), the lines a person signs and their rowsHash, and the
// values a read returns then read the same whatever the client, role or
// database set: a timestamptz prints with +00:00, an interval as 01:30:00,
// a float8 in its shortest exact form, money as $1,234.50, bytea as
// \x00ff; and a revert parses the money it restores in the format the
// guard stored it. Call it first in the transaction.
func PinSession(ctx context.Context, q Querier) error {
	return execCall(ctx, q, sq.Expr(
		"pg_catalog.set_config('TimeZone', ?, true), pg_catalog.set_config('DateStyle', ?, true), "+
			"pg_catalog.set_config('IntervalStyle', ?, true), pg_catalog.set_config('extra_float_digits', ?, true), "+
			"pg_catalog.set_config('lc_monetary', ?, true), pg_catalog.set_config('bytea_output', ?, true)",
		PinnedTimeZone, PinnedDateStyle, PinnedIntervalStyle, PinnedExtraFloatDigits, PinnedLcMonetary, PinnedByteaOutput))
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
