package pgcatalog

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5"
)

// StructureLines returns one sorted line per fact about the structure of the
// relations session_user can read: the relation and its kind, each
// selectable column with its type and nullability, each constraint and each
// index definition. Row counts, sizes and scan counts are left out, so the
// lines change only when the structure does, which is what a fingerprint of
// the catalog needs.
func StructureLines(ctx context.Context, db Querier) ([]string, error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `WITH rel AS (
			SELECT c.oid, n.nspname || '.' || c.relname AS name, `+relationKind+` AS kind
			`+relationFrom+` AND `+readableTable+`
		)
		SELECT name || ':' || kind FROM rel
		UNION ALL
		SELECT rel.name || ':column:' || a.attname || ':' || pg_catalog.format_type(a.atttypid, a.atttypmod)
				|| ':' || (NOT a.attnotnull)::text
			FROM rel JOIN pg_catalog.pg_attribute a ON a.attrelid = rel.oid
			WHERE a.attnum > 0 AND NOT a.attisdropped
			AND pg_catalog.has_column_privilege(session_user, rel.oid, a.attnum, 'SELECT')
		UNION ALL
		SELECT rel.name || ':constraint:' || x.conname || ':' || pg_catalog.pg_get_constraintdef(x.oid)
			FROM rel JOIN pg_catalog.pg_constraint x ON x.conrelid = rel.oid
		UNION ALL
		SELECT rel.name || ':index:' || pg_catalog.pg_get_indexdef(i.indexrelid)
			FROM rel JOIN pg_catalog.pg_index i ON i.indrelid = rel.oid`)
	if err != nil {
		return nil, err
	}
	lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	// Sorted in Go so the order does not depend on the database collation.
	sort.Strings(lines)
	return lines, nil
}
