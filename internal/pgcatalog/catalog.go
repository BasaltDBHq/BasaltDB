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
	// Plain SQL: a pg_constraint join, not table DML. pg_constraint rather
	// than information_schema, which lists only tables the role owns or
	// holds a non-SELECT privilege on, so a read-only table showed no keys.
	rows, err := db.Query(ctx, `SELECT a.attname::text, rn.nspname::text, rc.relname::text, ra.attname::text
		FROM pg_catalog.pg_constraint k
		JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_class rc ON rc.oid = k.confrelid
		JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
		CROSS JOIN LATERAL unnest(k.conkey, k.confkey) WITH ORDINALITY AS u(attnum, refattnum, ord)
		JOIN pg_catalog.pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum
		JOIN pg_catalog.pg_attribute ra ON ra.attrelid = k.confrelid AND ra.attnum = u.refattnum
		WHERE k.contype = 'f' AND k.conparentid = 0 AND n.nspname = $1 AND c.relname = $2
		ORDER BY k.conname, u.ord`, schema, table)
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
