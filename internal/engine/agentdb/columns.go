package agentdb

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ColumnOrder reads the order of tables' columns (attnum) from pg_attribute,
// as the agent role sees the catalog: names only, which every role can read
// there itself. A table name is taken as the lines spell it, schema.name
// (parse_ident, which checks no privilege); one that does not resolve is
// left out.
type ColumnOrder struct {
	pool Pool
}

// NewColumnOrder returns the column order on pool. It panics on a nil pool.
func NewColumnOrder(pool Pool) *ColumnOrder {
	if pool == nil {
		panic("agentdb: pool required")
	}
	return &ColumnOrder{pool: pool}
}

const columnOrderSQL = `SELECT t.name, array_agg(a.attname::text ORDER BY a.attnum)
FROM unnest($1::text[]) AS t(name)
CROSS JOIN LATERAL pg_catalog.parse_ident(t.name) AS p(part)
JOIN pg_catalog.pg_namespace n ON n.nspname = p.part[1]
JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = p.part[2]
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE pg_catalog.array_length(p.part, 1) = 2
GROUP BY t.name`

// ColumnOrder maps each table to its columns in table order.
func (c *ColumnOrder) ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error) {
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, columnOrderSQL, tables)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for rows.Next() {
		var name string
		var cols []string
		if err := rows.Scan(&name, &cols); err != nil {
			rows.Close()
			return nil, err
		}
		out[name] = cols
	}
	rows.Close()
	return out, rows.Err()
}
