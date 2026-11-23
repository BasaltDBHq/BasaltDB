// Package ledger reads the guard's ledger the way an agent may (D6):
// through the basalt_meta agent views, which show the calling agent's own
// rows only and redact row keys and values of tables it cannot SELECT.
// basalt log and the engine's run_history use it.
package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// ErrInvalidParams is returned for list params the handler should have
// rejected or clamped.
var ErrInvalidParams = errors.New("invalid list params")

// ChangeSortSpec whitelists the change list sort: newest first by default.
var ChangeSortSpec = pagination.SortSpec{
	Default: "-id",
	Allowed: map[string]struct{}{"id": {}, "-id": {}},
}

// ListChanges returns one page of the calling agent's change records.
func ListChanges(ctx context.Context, q guard.Querier, p action.ChangeListParams) (pagination.Page[action.Change], error) {
	sql, args, _, err := changePage(p)
	if err != nil {
		return pagination.Page[action.Change]{}, err
	}
	return collectChanges(ctx, q, p, sql, args, func(row pgx.CollectableRow, c *action.Change) error {
		return row.Scan(changeDest(c)...)
	})
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
	"reverted_by",
}

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
	b := psql.Select(changeColumns...).
		From("basalt_meta.agent_changes").
		OrderBy(order).
		Limit(uint64(p.Limit) + 1)
	if p.RunID != uuid.Nil {
		b = b.Where(sq.Eq{colRunID: p.RunID.String()})
	}
	b, err = pagination.ApplyIDKeyset(b, colChangeID, sort.Desc, p.Cursor)
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
		&c.ActorKind, &c.RevertID, &c.RevertedBy,
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

// RowChanges returns the row-level ledger entries of the given changes in
// ledger order, keyed by change id. An agent's change touches at most 50
// rows (the row limit) and a revert at most 1000 (its line cap), so the
// result is bounded by the page of changes.
func RowChanges(ctx context.Context, q guard.Querier, changeIDs []uuid.UUID) (map[uuid.UUID][]action.RowChange, error) {
	out := make(map[uuid.UUID][]action.RowChange, len(changeIDs))
	if len(changeIDs) == 0 {
		return out, nil
	}
	sql, args, err := rowChangeSelect(changeIDs).OrderBy("seq").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var r action.RowChange
		var key, before, after json.RawMessage
		if err := rows.Scan(&id, &r.Seq, &r.Table, &r.Op, &key, &before, &after,
			&r.Cascaded, &r.Redacted, &r.Pruned, &r.BasedOn, &r.BlindWrite); err != nil {
			return nil, err
		}
		// The images as Postgres printed them: decoded for the row, and
		// measured byte for byte for the summaries of its large values.
		if err := decodeImages(&r, key, before, after); err != nil {
			return nil, err
		}
		out[id] = append(out[id], r)
	}
	return out, rows.Err()
}

// rowChangeSelect selects the ROW_CHANGE ledger rows of changeIDs, columns
// named so a statement over them can select them again.
func rowChangeSelect(changeIDs []uuid.UUID) sq.SelectBuilder {
	ids := make([]string, 0, len(changeIDs))
	for _, id := range changeIDs {
		ids = append(ids, id.String())
	}
	return psql.Select(colChangeID, "seq", "coalesce(table_name, '') AS table_name", "coalesce(op, '') AS op",
		"row_key", "old_row", "new_row", "coalesce((detail->>'cascaded')::boolean, false) AS cascaded", "redacted",
		"values_pruned", "detail->'basedOn' AS based_on", "coalesce((detail->>'blindWrite')::boolean, false) AS blind_write").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": "ROW_CHANGE", colChangeID: ids})
}

// decodeImages sets r's key, before and after maps from the images' JSON
// text and the summaries of the values in them that cost over 1 MiB.
func decodeImages(r *action.RowChange, key, before, after json.RawMessage) error {
	for _, img := range []struct {
		text  json.RawMessage
		into  *map[string]any
		marks *map[string]string
	}{{key, &r.Key, &r.Marks.Key}, {before, &r.Before, &r.Marks.Before}, {after, &r.After, &r.Marks.After}} {
		if len(img.text) == 0 {
			continue
		}
		if err := json.Unmarshal(img.text, img.into); err != nil {
			return err
		}
		marks, err := largevalue.ImageMarks(img.text)
		if err != nil {
			return err
		}
		*img.marks = marks
	}
	return nil
}
