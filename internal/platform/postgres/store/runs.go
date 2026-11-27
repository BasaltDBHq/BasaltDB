package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// MaxRunResources is how many resources a run summary names (list_runs); a
// run that wrote to more is marked ResourcesTruncated.
const MaxRunResources = 10

// runIDColumn is the run list's sort and keyset column.
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
	"COUNT(c.change_id) FILTER (WHERE c.status = 'APPLIED' AND c.op = 'READ') AS reads",
	"coalesce(sum(c.rows) FILTER (WHERE "+writtenWrite+"), 0) AS rows_written",
	// One more resource than a summary names, to tell a run that wrote to
	// more than MaxRunResources.
	fmt.Sprintf("coalesce((array_agg(DISTINCT c.table_name ORDER BY c.table_name) FILTER (WHERE %s AND c.table_name IS NOT NULL))[1:%d], '{}') AS resources",
		writtenWrite, MaxRunResources+1),
).From("basalt_meta.agent_changes c").Where("c.run_id = r.run_id")

// listRunsRaw is ListRuns before MapError.
// looseReadsID is the id of a LOOSE_READS item, which has none of its own:
// the nil UUID, so the keyset key (at, kind, id) is the same shape for every
// kind.
const looseReadsID = "00000000-0000-0000-0000-000000000000"

// looseReadsWhere picks the agent's reads outside any run. A read in a run
// belongs to that run; a refused one is not a read the agent saw.
const looseReadsWhere = `c.op = 'READ' AND c.run_id IS NULL AND c.status = 'APPLIED'`

// listRunsKeys are the three kinds of list_runs item with the key they
// order by: (at, kind, id). Reverts are the ones the person signed (a batched
// plan's signature, or the one-call apply that signs and applies at once); reads
// outside a run are grouped per UTC hour, keyed by the hour's start.
const listRunsKeys = `SELECT 'RUN'::text AS kind, r.started_at AS ts, r.run_id AS id FROM basalt_meta.agent_runs r
	UNION ALL
	SELECT 'REVERT', coalesce(v.signed_at, v.applied_at), v.revert_id FROM basalt_meta.agent_reverts v
	 WHERE coalesce(v.signed_at, v.applied_at) IS NOT NULL
	UNION ALL
	SELECT 'LOOSE_READS', pg_catalog.date_trunc('hour', c.at, 'UTC'), '` + looseReadsID + `'::uuid
	  FROM basalt_meta.agent_changes c WHERE ` + looseReadsWhere + ` GROUP BY 2`

// listRunsPage is one page of list_runs: the keys first, cut to the page,
// and only then each item's details, so a run's aggregate is computed for
// the runs on the page and no others. The agent views show the calling
// agent's own records only.
const listRunsPage = `WITH k AS (%s), page AS (
	SELECT * FROM k WHERE %s ORDER BY ts %[3]s, kind %[3]s, id %[3]s LIMIT %s
)
SELECT p.kind, p.ts, p.id,
	r.task_id, coalesce(r.intent, ''), a.last_change_at,
	coalesce(a.applied, 0), coalesce(a.held, 0), coalesce(a.refused, 0), coalesce(a.reverted, 0), coalesce(a.reads, 0),
	coalesce(a.rows_written, 0), coalesce(a.resources, '{}'),
	v.scope, v.scope_id, coalesce(v.intent, ''), coalesce(coalesce(v.restored, v.rows), 0), coalesce(coalesce(v.skipped_now, v.skipped), 0),
	coalesce(l.reads, 0), coalesce(l.resources, '{}')
FROM page p
LEFT JOIN basalt_meta.agent_runs r ON p.kind = 'RUN' AND r.run_id = p.id
LEFT JOIN LATERAL (%s) a ON p.kind = 'RUN'
LEFT JOIN basalt_meta.agent_reverts v ON p.kind = 'REVERT' AND v.revert_id = p.id
LEFT JOIN LATERAL (
	SELECT count(c.change_id)::int AS reads,
		(array_agg(DISTINCT c.table_name ORDER BY c.table_name) FILTER (WHERE c.table_name IS NOT NULL))[1:%d] AS resources
	  FROM basalt_meta.agent_changes c
	 WHERE ` + looseReadsWhere + ` AND c.at >= p.ts AND c.at < p.ts + interval '1 hour'
) l ON p.kind = 'LOOSE_READS'
ORDER BY p.ts %[3]s, p.kind %[3]s, p.id %[3]s`

func (s *Store) listRunsRaw(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunListItem], error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return pagination.Page[action.RunListItem]{}, fmt.Errorf("%w: limit %d", ledger.ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ledger.RunSortSpec)
	if err != nil {
		return pagination.Page[action.RunListItem]{}, fmt.Errorf("%w: %w", ledger.ErrInvalidParams, err)
	}
	where, args, err := runKeyset(p, sort.Desc)
	if err != nil {
		return pagination.Page[action.RunListItem]{}, fmt.Errorf("%w: %w", ledger.ErrInvalidParams, err)
	}
	direction := "ASC"
	if sort.Desc {
		direction = "DESC"
	}
	aggregate, _, err := runAggregate.ToSql()
	if err != nil {
		return pagination.Page[action.RunListItem]{}, err
	}
	sql := fmt.Sprintf(listRunsPage, listRunsKeys, where, direction, fmt.Sprint(p.Limit+1), aggregate, MaxRunResources+1)
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[action.RunListItem]{}, err
	}
	items, err := pgx.CollectRows(rows, scanRunListItem)
	if err != nil {
		return pagination.Page[action.RunListItem]{}, err
	}
	page := pagination.Page[action.RunListItem]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		last := page.Items[p.Limit-1]
		page.NextCursor = pagination.EncodeTimeCursor(last.At, last.Kind, itemID(last))
	}
	return page, nil
}

// itemID is the id a list_runs item is keyed by.
func itemID(it action.RunListItem) uuid.UUID {
	switch it.Kind {
	case action.RunItemRun:
		return it.Run.ID
	case action.RunItemRevert:
		return it.Revert.ID
	}
	return uuid.Nil
}

// runKeyset is the WHERE of the key page: the time range and the cursor, as
// SQL over (ts, kind, id) with its arguments. The time range filters each
// kind by its own time: the run's start, the revert's signature, the hour's
// start.
func runKeyset(p action.RunListParams, desc bool) (string, []any, error) {
	conds, args := []string{"true"}, []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if p.StartTime != nil {
		conds = append(conds, "ts >= "+arg(*p.StartTime))
	}
	if p.EndTime != nil {
		conds = append(conds, "ts < "+arg(*p.EndTime))
	}
	if p.Cursor != "" {
		at, kind, id, err := pagination.DecodeTimeCursor(p.Cursor)
		if err != nil {
			return "", nil, err
		}
		op := ">"
		if desc {
			op = "<"
		}
		conds = append(conds, fmt.Sprintf("(ts, kind, id) %s (%s::timestamptz, %s::text, %s::uuid)", op, arg(at), arg(kind), arg(id)))
	}
	return strings.Join(conds, " AND "), args, nil
}

func scanRunListItem(row pgx.CollectableRow) (action.RunListItem, error) {
	var (
		it                               action.RunListItem
		id                               uuid.UUID
		taskID                           uuid.NullUUID
		intent, revertIntent             string
		lastChangeAt                     *time.Time
		applied, held, refused, reverted int
		reads, rowsWritten               int
		resources                        []string
		scope                            *string
		scopeID                          uuid.NullUUID
		restored, skipped                int
		looseReads                       int
		looseResources                   []string
	)
	err := row.Scan(&it.Kind, &it.At, &id, &taskID, &intent, &lastChangeAt,
		&applied, &held, &refused, &reverted, &reads, &rowsWritten, &resources,
		&scope, &scopeID, &revertIntent, &restored, &skipped,
		&looseReads, &looseResources)
	if err != nil {
		return it, err
	}
	switch it.Kind {
	case action.RunItemRun:
		it.Run = action.RunSummary{
			ID: id, TaskID: taskID, Intent: intent, StartedAt: it.At, LastChangeAt: lastChangeAt,
			Applied: applied, Held: held, Refused: refused, Reverted: reverted, Reads: reads,
			RowsWritten: rowsWritten, Resources: resources,
		}
		if len(resources) > MaxRunResources {
			it.Run.Resources, it.Run.ResourcesTruncated = resources[:MaxRunResources], true
		}
	case action.RunItemRevert:
		it.Revert = action.RevertSummary{ID: id, ScopeID: scopeID, SignedAt: it.At, Restored: restored, Skipped: skipped, Intent: revertIntent}
		if scope != nil {
			it.Revert.Scope = *scope
		}
	default:
		it.Loose = action.LooseReads{From: it.At, To: it.At.Add(time.Hour), Reads: looseReads, Resources: looseResources}
		if len(looseResources) > MaxRunResources {
			it.Loose.Resources, it.Loose.ResourcesTruncated = looseResources[:MaxRunResources], true
		}
	}
	return it, nil
}
