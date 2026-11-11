// Package pgcatalog reads key and foreign-key metadata from a Postgres
// catalog. M1 uses it to find tables reachable by FK cascade from
// agent-writable tables and the primary key that becomes target.key in the
// change record; M3 uses it to order reverts.
package pgcatalog

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Querier is the part of a pgx connection or pool this package needs.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ForeignKey is one column of a foreign key on a table.
type ForeignKey struct {
	Column    string
	RefSchema string
	RefTable  string
	RefColumn string
}

// ForeignKeys returns the outgoing foreign-key columns of schema.table, in
// key column order.
func ForeignKeys(ctx context.Context, db Querier, schema, table string) ([]ForeignKey, error) {
	// Plain SQL: an information_schema catalog join, not table DML.
	rows, err := db.Query(ctx, `SELECT kcu.column_name, ccu.table_schema, ccu.table_name, ccu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
			ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage ccu
			ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
		WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = $1 AND tc.table_name = $2
		ORDER BY kcu.ordinal_position`, schema, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ForeignKey, error) {
		var fk ForeignKey
		err := row.Scan(&fk.Column, &fk.RefSchema, &fk.RefTable, &fk.RefColumn)
		return fk, err
	})
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
