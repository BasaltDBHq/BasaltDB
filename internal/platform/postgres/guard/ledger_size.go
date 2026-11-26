package guard

import (
	"context"

	sq "github.com/Masterminds/squirrel"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// LedgerBytes is the size of every table, index and TOAST table in
// basalt_meta, in bytes. It needs no privilege on basalt_meta, so the agent's
// own role can read it. A database without the guard fails the regnamespace
// cast; status reads the guard first and handles that case.
func LedgerBytes(ctx context.Context, q Querier) (int64, error) {
	sql, args, err := sqlport.Builder.Select("coalesce(sum(pg_catalog.pg_total_relation_size(c.oid)), 0)::bigint").
		From("pg_catalog.pg_class c").
		Where("c.relnamespace = 'basalt_meta'::pg_catalog.regnamespace").
		Where(sq.Eq{"c.relkind": []string{"r", "p", "m"}}).ToSql()
	if err != nil {
		return 0, err
	}
	var n int64
	err = q.QueryRow(ctx, sql, args...).Scan(&n)
	return n, err
}
