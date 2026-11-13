package guard

import "context"

// LedgerBytes is the size of every table, index and TOAST table in
// basalt_meta, in bytes. It needs no privilege on basalt_meta, so the agent's
// own role can read it. A database without the guard fails the regnamespace
// cast; status reads the guard first and handles that case.
func LedgerBytes(ctx context.Context, q Querier) (int64, error) {
	// Raw SQL: the regnamespace cast and the sum over pg_class are not expressible in squirrel.
	const sql = `SELECT coalesce(sum(pg_catalog.pg_total_relation_size(c.oid)), 0)::bigint
FROM pg_catalog.pg_class c
WHERE c.relnamespace = 'basalt_meta'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p', 'm')`
	var n int64
	err := q.QueryRow(ctx, sql).Scan(&n)
	return n, err
}
