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
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
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

// ChangeListParams lists change records. RunID uuid.Nil means every run.
// The handler applies pagination defaults and the clamp before calling.
type ChangeListParams struct {
	pagination.Params
	RunID uuid.UUID
}

// Change is one change record (CONTRACT.md "The change record").
type Change struct {
	ID           uuid.UUID
	At           time.Time
	Agent        string
	RunID        uuid.NullUUID
	TaskID       uuid.NullUUID
	Intent       string
	Op           string
	Table        string
	Statement    string
	Params       json.RawMessage
	Rows         int
	CascadedRows int
	DurationMs   *int
	Status       string
	Code         string
	Reason       string
	// ActorKind is AGENT, or PERSON for a revert (M3).
	ActorKind string
	// RevertID is the revert a REVERT change carried out.
	RevertID uuid.NullUUID
	// RevertedBy lists the revert changes that restored rows of this one.
	RevertedBy []uuid.UUID
	// LargeValues names the statement or params left out of an agent's read
	// (ListChangesMarked; CONTRACT.md, Large values); nil on the person's.
	LargeValues []largevalue.Entry
}

// RowChange is one row a change wrote, cascades included. Key, Before and
// After are nil when Redacted (the agent cannot SELECT the table) or
// Pruned (older than 30 days).
type RowChange struct {
	Seq      int64
	Table    string
	Op       string
	Key      map[string]any
	Before   map[string]any
	After    map[string]any
	Cascaded bool
	Redacted bool
	Pruned   bool
	// BasedOn is the version of the row the run had read (M1.5), nil when
	// the run never read it (BlindWrite) or for an insert or cascaded row.
	BasedOn    *BasedOn
	BlindWrite bool
	// LargeValues names the values left out of an agent's read
	// (RowChangesMarked), and KeyLeftOut, BeforeLeftOut and AfterLeftOut
	// the images left out whole: absent on the wire, never null.
	LargeValues                             []largevalue.Entry
	KeyLeftOut, BeforeLeftOut, AfterLeftOut bool
}

// BasedOn is the row version a write was based on (CONTRACT.md).
type BasedOn struct {
	Version  string    `json:"version"`
	ChangeID uuid.UUID `json:"changeId"`
}

// ListChanges returns one page of the calling agent's change records.
func ListChanges(ctx context.Context, q guard.Querier, p ChangeListParams) (pagination.Page[Change], error) {
	sql, args, _, err := changePage(p)
	if err != nil {
		return pagination.Page[Change]{}, err
	}
	return collectChanges(ctx, q, p, sql, args, func(row pgx.CollectableRow, c *Change) error {
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
func changePage(p ChangeListParams) (string, []any, bool, error) {
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
func changeDest(c *Change) []any {
	return []any{
		&c.ID, &c.At, &c.Agent, &c.RunID, &c.TaskID, &c.Intent, &c.Op, &c.Table, &c.Statement,
		&c.Params, &c.Rows, &c.CascadedRows, &c.DurationMs, &c.Status, &c.Code, &c.Reason,
		&c.ActorKind, &c.RevertID, &c.RevertedBy,
	}
}

// collectChanges runs sql and returns its rows as one page of p.
func collectChanges(ctx context.Context, q guard.Querier, p ChangeListParams, sql string, args []any,
	scan func(pgx.CollectableRow, *Change) error,
) (pagination.Page[Change], error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[Change]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Change, error) {
		var c Change
		err := scan(row, &c)
		return c, err
	})
	if err != nil {
		return pagination.Page[Change]{}, err
	}
	page := pagination.Page[Change]{Items: items}
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
func RowChanges(ctx context.Context, q guard.Querier, changeIDs []uuid.UUID) (map[uuid.UUID][]RowChange, error) {
	out := make(map[uuid.UUID][]RowChange, len(changeIDs))
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
		var r RowChange
		if err := rows.Scan(&id, &r.Seq, &r.Table, &r.Op, &r.Key, &r.Before, &r.After,
			&r.Cascaded, &r.Redacted, &r.Pruned, &r.BasedOn, &r.BlindWrite); err != nil {
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
