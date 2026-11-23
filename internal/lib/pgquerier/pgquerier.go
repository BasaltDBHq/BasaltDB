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
