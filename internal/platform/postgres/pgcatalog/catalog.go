// Package pgcatalog reads a Postgres catalog: the relations, columns, keys
// and grants describe and basalt access report, and a table's primary key.
package pgcatalog

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Querier is the part of a pgx connection or pool this package needs.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}
