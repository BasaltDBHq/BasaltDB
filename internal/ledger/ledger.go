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
}

// BasedOn is the row version a write was based on (CONTRACT.md).
type BasedOn struct {
	Version  string    `json:"version"`
	ChangeID uuid.UUID `json:"changeId"`
}

// ListChanges returns one page of the calling agent's change records.
func ListChanges(ctx context.Context, q guard.Querier, p ChangeListParams) (pagination.Page[Change], error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return pagination.Page[Change]{}, fmt.Errorf("%w: limit %d", ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ChangeSortSpec)
	if err != nil {
		return pagination.Page[Change]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	order := "change_id"
	if sort.Desc {
		order += " DESC"
	}
	b := psql.Select("change_id", "at", "agent", "run_id", "task_id", "coalesce(intent, '')", "coalesce(op, '')",
		"coalesce(table_name, '')", "coalesce(statement, '')", "params", "rows", "cascaded_rows", "duration_ms",
		"status", "coalesce(code, '')", "coalesce(reason, '')", "actor_kind", "revert_id", "reverted_by").
		From("basalt_meta.agent_changes").
		OrderBy(order).
		Limit(uint64(p.Limit) + 1)
	if p.RunID != uuid.Nil {
		b = b.Where(sq.Eq{"run_id": p.RunID.String()})
	}
	b, err = pagination.ApplyIDKeyset(b, "change_id", sort.Desc, p.Cursor)
	if err != nil {
		return pagination.Page[Change]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	sql, args, err := b.ToSql()
	if err != nil {
		return pagination.Page[Change]{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[Change]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Change, error) {
		var c Change
		err := row.Scan(&c.ID, &c.At, &c.Agent, &c.RunID, &c.TaskID, &c.Intent, &c.Op, &c.Table, &c.Statement,
			&c.Params, &c.Rows, &c.CascadedRows, &c.DurationMs, &c.Status, &c.Code, &c.Reason,
			&c.ActorKind, &c.RevertID, &c.RevertedBy)
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
	ids := make([]string, 0, len(changeIDs))
	for _, id := range changeIDs {
		ids = append(ids, id.String())
	}
	sql, args, err := psql.Select("change_id", "seq", "coalesce(table_name, '')", "coalesce(op, '')",
		"row_key", "old_row", "new_row", "coalesce((detail->>'cascaded')::boolean, false)", "redacted", "values_pruned",
		"detail->'basedOn'", "coalesce((detail->>'blindWrite')::boolean, false)").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": "ROW_CHANGE", "change_id": ids}).
		OrderBy("seq").
		ToSql()
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
