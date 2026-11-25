package ledger

import (
	"context"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pglargevalue"
)

// ErrRevertNotFound is a revert id the calling role did not prepare.
var ErrRevertNotFound = errors.New("revert not found")

// Revert statuses (basalt_meta.agent_reverts).
const (
	RevertPending  = "PENDING"
	RevertApplying = "APPLYING"
	RevertApplied  = "APPLIED"
	RevertExpired  = "EXPIRED"
	// RevertRejected is a revert the person rejected on the revert page
	// (basalt_meta version 23): nothing was reverted.
	RevertRejected = "REJECTED"
)

func revertSelect(ctx context.Context) sq.SelectBuilder {
	return withRequest(ctx, psql.Select(colRevertID, "status", "scope", "scope_id", "intent", "rows", "skipped", "expires_at",
		"coalesce(binding_text, '')", "batched", "signed_at", "apply_by", "batches",
		"coalesce(restored, 0)", "coalesce(skipped_now, 0)", "coalesce(pending, 0)", "change_id", "widened",
		"rejected_at", "coalesce(reject_note, '')", "created_at").
		From("basalt_meta.agent_reverts"))
}

func scanRevert(row pgx.CollectableRow) (action.Revert, error) {
	var r action.Revert
	err := row.Scan(&r.ID, &r.Status, &r.Scope, &r.ScopeID, &r.Intent, &r.Rows, &r.Skipped, &r.ExpiresAt, &r.BindingText,
		&r.Batched, &r.SignedAt, &r.ApplyBy, &r.Batches,
		&r.Progress.Restored, &r.Progress.Skipped, &r.Progress.Pending, &r.ChangeID, &r.Widened,
		&r.RejectedAt, &r.RejectNote, &r.CreatedAt, &r.Lines, &r.LinesLeftOut, &r.LinesCost)
	return r, err
}

// FindRevert returns a revert the calling role prepared.
func FindRevert(ctx context.Context, q guard.Querier, id uuid.UUID) (action.Revert, error) {
	sql, args, err := revertSelect(ctx).Where(sq.Eq{colRevertID: id.String()}).ToSql()
	if err != nil {
		return action.Revert{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return action.Revert{}, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanRevert)
	if errors.Is(err, pgx.ErrNoRows) {
		return action.Revert{}, ErrRevertNotFound
	}
	return r, err
}

// colRevertID is the revert id column of basalt_meta.agent_reverts.
const colRevertID = "revert_id"

// ListOpenReverts returns one page of the calling role's reverts waiting
// for the person's signature (PENDING, not expired) or for the role's
// batches (APPLYING), keyset on the revert id as held writes are, so the
// two lists merge in one order (list_pending, LP-1).
func ListOpenReverts(ctx context.Context, q guard.Querier, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	switch p.Status {
	case "", RevertPending, RevertApplying:
	default:
		return pagination.Page[action.Revert]{}, fmt.Errorf("%w: status %q", ErrInvalidParams, p.Status)
	}
	l := openList[action.Revert]{
		selectAll: revertSelect(ctx), idColumn: colRevertID, statuses: []string{RevertPending, RevertApplying},
		scan: scanRevert, id: func(r action.Revert) uuid.UUID { return r.ID },
	}
	return l.page(ctx, q, p.Params, p.Status)
}

// ListRevertLines returns one page of the lines of a batched plan the
// calling role prepared, keyset on the line number.
func ListRevertLines(ctx context.Context, q guard.Querier, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	sql, args, err := revertLinePage(p)
	if err != nil {
		return pagination.Page[action.RevertLine]{}, err
	}
	return collectRevertLines(ctx, q, p, sql, args)
}

// ListRevertLinesMarked is ListRevertLines for an agent (revert_plan): each
// line's values and images too large for the agent are left out and named
// in its largeValues, and its changeIds cut to the first
// largevalue.MaxChangeIDs (CONTRACT.md, Large values).
func ListRevertLinesMarked(ctx context.Context, q guard.Querier, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	page, args, err := revertLinePage(p)
	if err != nil {
		return pagination.Page[action.RevertLine]{}, err
	}
	// Plain SQL: a recursive CTE over the page (pglargevalue.ElideLines).
	// The line past the limit only tells that another page follows: its
	// text is never read (a page at limit 1 holds one line).
	sql := pglargevalue.With + `lv_page AS MATERIALIZED (SELECT x.*, row_number() OVER (ORDER BY line_no) > ` +
		fmt.Sprint(p.Limit) + ` AS lv_more FROM (` + page + `) x), ` +
		pglargevalue.ElideLines(`SELECT line_no AS item, line::jsonb AS line FROM lv_page WHERE line <> '' AND NOT lv_more`) + `
		SELECT p.line_no, CASE WHEN p.lv_more THEN '' ELSE coalesce(e.line::text, p.line) END, p.outcome, p.conflict, p.sql_state, p.batch
		FROM lv_page p LEFT JOIN lv_lines e ON e.item = p.line_no
		ORDER BY p.line_no`
	return collectRevertLines(ctx, q, p, sql, args)
}

// revertLinePage is the SQL of one page of a plan's lines, one more than
// the limit.
func revertLinePage(p action.RevertLineParams) (string, []any, error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return "", nil, fmt.Errorf("%w: limit %d", ErrInvalidParams, p.Limit)
	}
	if p.Sort != "" {
		return "", nil, fmt.Errorf("%w: plan lines come in execution order; no sort", ErrInvalidParams)
	}
	b := psql.Select("line_no", "coalesce(line, '') AS line", "outcome", "coalesce(conflict, '') AS conflict",
		"coalesce(sql_state, '') AS sql_state", "batch").
		From("basalt_meta.agent_revert_lines").Where(sq.Eq{"revert_id": p.RevertID.String()}).
		OrderBy("line_no").Limit(uint64(p.Limit) + 1)
	switch p.Outcome {
	case "":
	case guardmodel.OutcomePending, guardmodel.OutcomeRestored, guardmodel.OutcomeSkipped:
		b = b.Where(sq.Eq{"outcome": p.Outcome})
	default:
		return "", nil, fmt.Errorf("%w: outcome %q", ErrInvalidParams, p.Outcome)
	}
	b, err := applySeqKeyset(b, "line_no", false, p.Cursor)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return b.ToSql()
}

// collectRevertLines runs sql and returns its rows as one page of p.
func collectRevertLines(ctx context.Context, q guard.Querier, p action.RevertLineParams, sql string, args []any) (pagination.Page[action.RevertLine], error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[action.RevertLine]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (action.RevertLine, error) {
		var l action.RevertLine
		err := row.Scan(&l.No, &l.Text, &l.Outcome, &l.Conflict, &l.StoreCode, &l.Batch)
		return l, err
	})
	if err != nil {
		return pagination.Page[action.RevertLine]{}, err
	}
	page := pagination.Page[action.RevertLine]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		page.NextCursor = pagination.EncodeSeqCursor(int64(page.Items[p.Limit-1].No))
	}
	return page, nil
}
