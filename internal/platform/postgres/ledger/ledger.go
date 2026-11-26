// Package ledger reads the guard's ledger the way an agent may (D6):
// through the basalt_meta agent views, which show the calling agent's own
// rows only and redact row keys and values of tables it cannot SELECT.
// basalt log and the engine's run_history use it.
package ledger

import (
	"context"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// ErrInvalidParams is returned for list params the handler should have
// rejected or clamped.
var ErrInvalidParams = errors.New("invalid list params")

// ChangeSortSpec whitelists the change list sort: newest first by default.
var ChangeSortSpec = pagination.SortSpec{
	Default: "-id",
	Allowed: map[string]struct{}{"id": {}, "-id": {}},
}

// Column names the change lists share.
const (
	colChangeID = "change_id"
	colRunID    = "run_id"
)

// changeColumns are the change record's columns, named so a statement over
// the page can select them again.
var changeColumns = []string{
	colChangeID, "at", "agent", colRunID, "task_id", "coalesce(intent, '') AS intent", "coalesce(op, '') AS op",
	"coalesce(table_name, '') AS table_name", "coalesce(statement, '') AS statement", "params", "rows", "cascaded_rows",
	"duration_ms", "status", "coalesce(code, '') AS code", "coalesce(reason, '') AS reason", "actor_kind", "revert_id",
	"reverted_by", changeVerb,
}

// changeVerb is the store's word for a change's request (CONTRACT.md,
// Stores, Operations): agent_changes has no verb, so it is the one on the
// change's latest ledger row that records the request (CHANGE, READ,
// REFUSED, APPROVAL_PENDING). An upsert whose rows all update is op UPDATE
// with verb INSERT, so it is read, never derived from op. Plain SQL: a
// correlated subquery, one index lookup per change (ledger_change).
const changeVerb = `coalesce((SELECT l.verb FROM basalt_meta.agent_ledger l
	WHERE l.change_id = agent_changes.change_id AND l.kind IN ('CHANGE', 'READ', 'REFUSED', 'APPROVAL_PENDING')
	ORDER BY l.seq DESC LIMIT 1), '') AS verb`

// changePage is the SQL of one page of change records (one row more than
// the limit, to tell whether another page follows), and whether it is
// sorted newest first.
func changePage(p action.ChangeListParams) (string, []any, bool, error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return "", nil, false, fmt.Errorf("%w: limit %d", ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ChangeSortSpec)
	if err != nil {
		return "", nil, false, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	order := colChangeID
	if sort.Desc {
		order += descending
	}
	b := sqlport.Builder.Select(changeColumns...).
		From("basalt_meta.agent_changes").
		OrderBy(order).
		Limit(uint64(p.Limit) + 1)
	if p.RunID != uuid.Nil {
		b = b.Where(sq.Eq{colRunID: p.RunID.String()})
	}
	b, err = applyIDKeyset(b, colChangeID, sort.Desc, p.Cursor)
	if err != nil {
		return "", nil, false, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	sql, args, err := b.ToSql()
	return sql, args, sort.Desc, err
}

// changeDest are the scan destinations of changeColumns.
func changeDest(c *action.Change) []any {
	return []any{
		&c.ID, &c.At, &c.Agent, &c.RunID, &c.TaskID, &c.Intent, &c.Op, &c.Table, &c.Statement,
		&c.Params, &c.Rows, &c.CascadedRows, &c.DurationMs, &c.Status, &c.Code, &c.Reason,
		&c.ActorKind, &c.RevertID, &c.RevertedBy, &c.Verb,
	}
}

// collectChanges runs sql and returns its rows as one page of p.
func collectChanges(ctx context.Context, q guard.Querier, p action.ChangeListParams, sql string, args []any,
	scan func(pgx.CollectableRow, *action.Change) error,
) (pagination.Page[action.Change], error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[action.Change]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (action.Change, error) {
		var c action.Change
		err := scan(row, &c)
		return c, err
	})
	if err != nil {
		return pagination.Page[action.Change]{}, err
	}
	page := pagination.Page[action.Change]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		page.NextCursor = pagination.EncodeIDCursor(page.Items[p.Limit-1].ID.String())
	}
	return page, nil
}

// rowChangeSelect selects the ROW_CHANGE ledger rows of changeIDs, columns
// named so a statement over them can select them again.
func rowChangeSelect(changeIDs []uuid.UUID) sq.SelectBuilder {
	ids := make([]string, 0, len(changeIDs))
	for _, id := range changeIDs {
		ids = append(ids, id.String())
	}
	return sqlport.Builder.Select(colChangeID, "seq", "coalesce(table_name, '') AS table_name", "coalesce(op, '') AS op",
		"row_key", "old_row", "new_row", "coalesce((detail->>'cascaded')::boolean, false) AS cascaded", "redacted",
		"values_pruned", "detail->'basedOn' AS based_on", "coalesce((detail->>'blindWrite')::boolean, false) AS blind_write").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": "ROW_CHANGE", colChangeID: ids})
}
