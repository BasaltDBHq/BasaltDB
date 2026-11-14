package ledger

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// descending is the ORDER BY suffix of a list sorted newest first.
const descending = " DESC"

// openList is one of the open-item lists list_pending merges: held writes
// and reverts, each keyset on its UUIDv7 id so the two merge in one order.
type openList[T any] struct {
	selectAll sq.SelectBuilder
	idColumn  string
	// statuses are every open status; status, when set, must be one.
	statuses []string
	scan     func(pgx.CollectableRow) (T, error)
	id       func(T) uuid.UUID
	// wrap, when set, is the statement that reads the page whose SQL it
	// is given, in the same order (desc: newest first).
	wrap func(page string, desc bool, limit int) string
}

// page returns one page of l with status ("" for every open status).
func (l openList[T]) page(ctx context.Context, q guard.Querier, p pagination.Params, status string) (pagination.Page[T], error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return pagination.Page[T]{}, fmt.Errorf("%w: limit %d", ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ApprovalSortSpec)
	if err != nil {
		return pagination.Page[T]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	order := l.idColumn
	if sort.Desc {
		order += descending
	}
	statuses := l.statuses
	if status != "" {
		statuses = []string{status}
	}
	b := l.selectAll.Where(sq.Eq{"status": statuses}).OrderBy(order).Limit(uint64(p.Limit) + 1)
	if b, err = pagination.ApplyIDKeyset(b, l.idColumn, sort.Desc, p.Cursor); err != nil {
		return pagination.Page[T]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	sql, args, err := b.ToSql()
	if err != nil {
		return pagination.Page[T]{}, err
	}
	if l.wrap != nil {
		sql = l.wrap(sql, sort.Desc, p.Limit)
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[T]{}, err
	}
	items, err := pgx.CollectRows(rows, l.scan)
	if err != nil {
		return pagination.Page[T]{}, err
	}
	out := pagination.Page[T]{Items: items}
	if len(items) > p.Limit {
		out.Items = items[:p.Limit]
		out.NextCursor = pagination.EncodeIDCursor(l.id(out.Items[p.Limit-1]).String())
	}
	return out, nil
}
