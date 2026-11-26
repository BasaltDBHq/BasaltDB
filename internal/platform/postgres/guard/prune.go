package guard

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// PruneResult counts what Prune removed.
type PruneResult struct {
	ValuesPruned int64
	RowsDeleted  int64
}

// Prune applies retention (D10): row values older than 30 days are nulled,
// ledger metadata older than 1 year is deleted, and the chain stays
// verifiable. The engine calls it from a timer as the agent role.
func Prune(ctx context.Context, q Querier) (PruneResult, error) {
	sql, args, err := sqlport.Builder.Select("(r->>'valuesPruned')::bigint", "(r->>'rowsDeleted')::bigint").
		From("basalt_meta.prune() r").ToSql()
	if err != nil {
		return PruneResult{}, err
	}
	var res PruneResult
	err = q.QueryRow(ctx, sql, args...).Scan(&res.ValuesPruned, &res.RowsDeleted)
	return res, err
}
