package postgres

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// MaxRunTables is how many tables a run summary names (list_runs); a run
// that wrote to more is marked TablesTruncated.
const MaxRunTables = 10

// runIDColumn is the run list's sort and keyset column.
const runIDColumn = "r.run_id"

// The filters of the per-run aggregate over agent_changes. A write is an
// INSERT, UPDATE or DELETE record; a revert's own record (op REVERT) has no
// run of the agent and never matches. CROSS JOIN LATERAL of an aggregate
// always yields one row, so a run with no change record gets zero counts
// (a left join in effect).
const (
	writeOps     = `c.op IN ('INSERT', 'UPDATE', 'DELETE')`
	writtenWrite = writeOps + ` AND c.status IN ('APPLIED', 'REVERTED')`
)

// runAggregate is one run's counts over its change records, joined
// LATERAL so it is computed only for the runs of the page (changes_run
// index). It has no arguments.
var runAggregate = sq.Select(
	"max(c.at) AS last_change_at",
	"COUNT(c.change_id) FILTER (WHERE c.status = 'APPLIED' AND "+writeOps+") AS applied",
	"COUNT(c.change_id) FILTER (WHERE c.status = 'APPROVAL_PENDING') AS held",
	"COUNT(c.change_id) FILTER (WHERE c.status = 'REFUSED') AS refused",
	"COUNT(c.change_id) FILTER (WHERE c.status = 'REVERTED' AND "+writeOps+") AS reverted",
	"COUNT(c.change_id) FILTER (WHERE c.status = 'APPLIED' AND c.op = 'SELECT') AS reads",
	"coalesce(sum(c.rows) FILTER (WHERE "+writtenWrite+"), 0) AS rows_written",
	// One more table than a summary names, to tell a run that wrote to
	// more than MaxRunTables.
	fmt.Sprintf("coalesce((array_agg(DISTINCT c.table_name ORDER BY c.table_name) FILTER (WHERE %s AND c.table_name IS NOT NULL))[1:%d], '{}') AS tables",
		writtenWrite, MaxRunTables+1),
).From("basalt_meta.agent_changes c").Where("c.run_id = r.run_id")

// listRunsRaw is ListRuns before MapError.
func (s *Store) listRunsRaw(ctx context.Context, p ledger.RunListParams) (pagination.Page[action.RunSummary], error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return pagination.Page[action.RunSummary]{}, fmt.Errorf("%w: limit %d", ledger.ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ledger.RunSortSpec)
	if err != nil {
		return pagination.Page[action.RunSummary]{}, fmt.Errorf("%w: %w", ledger.ErrInvalidParams, err)
	}
	order := runIDColumn
	if sort.Desc {
		order += " DESC"
	}
	b := psql.Select(runIDColumn, "r.task_id", "r.intent", "r.started_at", "a.last_change_at",
		"a.applied", "a.held", "a.refused", "a.reverted", "a.reads", "a.rows_written", "a.tables").
		From("basalt_meta.agent_runs r").
		JoinClause(runAggregate.Prefix("CROSS JOIN LATERAL (").Suffix(") a")).
		OrderBy(order).
		Limit(uint64(p.Limit) + 1)
	if p.StartTime != nil {
		b = b.Where(sq.GtOrEq{"r.started_at": *p.StartTime})
	}
	if p.EndTime != nil {
		b = b.Where(sq.Lt{"r.started_at": *p.EndTime})
	}
	b, err = runKeyset(b, sort.Desc, p.Cursor)
	if err != nil {
		return pagination.Page[action.RunSummary]{}, fmt.Errorf("%w: %w", ledger.ErrInvalidParams, err)
	}
	sql, args, err := b.ToSql()
	if err != nil {
		return pagination.Page[action.RunSummary]{}, err
	}
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[action.RunSummary]{}, err
	}
	items, err := pgx.CollectRows(rows, scanRunSummary)
	if err != nil {
		return pagination.Page[action.RunSummary]{}, err
	}
	page := pagination.Page[action.RunSummary]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		page.NextCursor = pagination.EncodeIDCursor(page.Items[p.Limit-1].ID.String())
	}
	return page, nil
}

// runKeyset continues after the cursor's run id: run_id < cursor for -id,
// run_id > cursor for id.
func runKeyset(b sq.SelectBuilder, desc bool, cursor string) (sq.SelectBuilder, error) {
	if cursor == "" {
		return b, nil
	}
	raw, err := pagination.DecodeIDCursor(cursor)
	if err != nil {
		return b, err
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return b, fmt.Errorf("invalid cursor: %w", err)
	}
	if desc {
		return b.Where(sq.Lt{runIDColumn: id.String()}), nil
	}
	return b.Where(sq.Gt{runIDColumn: id.String()}), nil
}

func scanRunSummary(row pgx.CollectableRow) (action.RunSummary, error) {
	var r action.RunSummary
	err := row.Scan(&r.ID, &r.TaskID, &r.Intent, &r.StartedAt, &r.LastChangeAt,
		&r.Applied, &r.Held, &r.Refused, &r.Reverted, &r.Reads, &r.RowsWritten, &r.Tables)
	if len(r.Tables) > MaxRunTables {
		r.Tables, r.TablesTruncated = r.Tables[:MaxRunTables], true
	}
	return r, err
}
