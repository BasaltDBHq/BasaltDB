// Package pgquerier is the part of a pgx connection, pool or transaction
// that code needs to run queries. Code that takes a database handle without
// importing a driver's pool types (a service port) names it.
package pgquerier

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier runs a statement or a query on a connection, pool or transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Rows, Row and Result are the answers of a driver-free query, written as
// unnamed interfaces so every package's types of the same shape are the same
// types.
type (
	Rows = interface {
		Close()
		Err() error
		Next() bool
		Scan(dest ...any) error
	}
	Row    = interface{ Scan(dest ...any) error }
	Result = interface{ RowsAffected() int64 }
)

// Port is the driver-free query port a service declares for itself (setuprun
// Querier): the same interface, so Neutral implements it and so does
// anything else of the same shape.
type Port = interface {
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Neutral is a Querier seen through driver-free types: what a service that
// names no driver declares as its own query port (the Querier of setuprun).
// It runs every call on the Querier it wraps, on the same connection or
// transaction, and passes every error through unchanged.
type Neutral struct{ q Querier }

// Neutralize wraps q.
func Neutralize(q Querier) Neutral { return Neutral{q: q} }

// Pgx returns the Querier n wraps.
func (n Neutral) Pgx() Querier { return n.q }

func (n Neutral) Exec(ctx context.Context, sql string, args ...any) (Result, error) {
	return n.q.Exec(ctx, sql, args...)
}

func (n Neutral) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := n.q.Query(ctx, sql, args...) //nolint:sqlclosecheck // the caller closes the rows it is handed
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (n Neutral) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return n.q.QueryRow(ctx, sql, args...)
}

// Unwrap returns the Querier inside q, which must come from Neutralize.
func Unwrap(q any) Querier {
	n, ok := q.(Neutral)
	if !ok {
		panic("pgquerier: Unwrap of a query port that did not come from Neutralize")
	}
	return n.Pgx()
}

// ReadOnlyTx runs fn in a read-only transaction on b (a pool or a
// connection), always rolled back: for reads that change nothing. It returns
// fn's error, or the error of beginning the transaction.
func ReadOnlyTx(b interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
},
) func(ctx context.Context, fn func(Port) error) error {
	return func(ctx context.Context, fn func(Port) error) error {
		tx, err := b.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		return fn(Neutralize(tx))
	}
}

// QueryText runs sql with every result column in Postgres's text format,
// and calls row with each row's raw values (nil for NULL, valid only during
// the call) and its columns' type OIDs. It returns row's error, or the
// query's.
func (n Neutral) QueryText(ctx context.Context, sql string, args []any, row func(raw [][]byte, typeOIDs []uint32) error) error {
	rows, err := n.q.Query(ctx, sql, append([]any{pgx.QueryResultFormats{pgx.TextFormatCode}}, args...)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var oids []uint32
	for rows.Next() {
		if oids == nil {
			fds := rows.FieldDescriptions()
			oids = make([]uint32, len(fds))
			for i, fd := range fds {
				oids[i] = fd.DataTypeOID
			}
		}
		if err := row(rows.RawValues(), oids); err != nil {
			return err
		}
	}
	return rows.Err()
}
