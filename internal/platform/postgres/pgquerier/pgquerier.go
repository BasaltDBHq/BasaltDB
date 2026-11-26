// Package pgquerier is the part of a pgx connection, pool or transaction
// that code needs to run queries, and the bridge from a pgx handle to the
// driver-free port of sqlport. It imports the driver and belongs to the
// Postgres adapters and the wiring: a service declares its own query port,
// and an inbound adapter that holds a pgx handle has its backend wrap it.
package pgquerier

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// Querier runs a statement or a query on a connection, pool or transaction.
// It is an unnamed interface, so a package that may not import this one
// (an inbound adapter) declares the same type for itself.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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

func (n Neutral) Exec(ctx context.Context, sql string, args ...any) (sqlport.Result, error) {
	return n.q.Exec(ctx, sql, args...)
}

func (n Neutral) Query(ctx context.Context, sql string, args ...any) (sqlport.Rows, error) {
	rows, err := n.q.Query(ctx, sql, args...) //nolint:sqlclosecheck // the caller closes the rows it is handed
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (n Neutral) QueryRow(ctx context.Context, sql string, args ...any) sqlport.Row {
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

// Of returns the Querier of q, a query port that carries its driver
// connection (a Pgx method, as Neutral and an inbound adapter's own port
// over a connection it holds have). Any other q is a programming error.
func Of(q any) Querier {
	p, ok := q.(interface{ Pgx() Querier })
	if !ok {
		panic("pgquerier: Of a query port that carries no driver connection")
	}
	return p.Pgx()
}

// ReadOnlyTx runs fn in a read-only transaction on b (a pool or a
// connection), always rolled back: for reads that change nothing. It returns
// fn's error, or the error of beginning the transaction.
func ReadOnlyTx(b interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
},
) func(ctx context.Context, fn func(sqlport.Port) error) error {
	return func(ctx context.Context, fn func(sqlport.Port) error) error {
		tx, err := b.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		return fn(Neutralize(tx))
	}
}
