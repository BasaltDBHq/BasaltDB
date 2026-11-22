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

// PrimaryKey returns the primary-key columns of schema.table in key order,
// or none when the table has no primary key.
func PrimaryKey(ctx context.Context, db Querier, schema, table string) ([]string, error) {
	// Plain SQL: a pg_catalog join with array_position, not table DML.
	rows, err := db.Query(ctx, `SELECT a.attname
		FROM pg_catalog.pg_index i
		JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)
		WHERE i.indisprimary AND n.nspname = $1 AND c.relname = $2
		ORDER BY array_position(i.indkey, a.attnum)`, schema, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
