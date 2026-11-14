package ledger

import (
	"context"
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

// Revert is a revert the calling role prepared (basalt_meta.agent_reverts).
// Lines are every line of a one-call revert, or a batched plan's sample.
// SignedAt, ApplyBy and the progress counts are set on batched plans.
type Revert struct {
	ID          uuid.UUID
	Status      string
	Scope       string
	ScopeID     uuid.UUID
	Intent      string
	Rows        int
	Skipped     int
	ExpiresAt   time.Time
	BindingText string
	Lines       []string
	Batched     bool
	SignedAt    *time.Time
	ApplyBy     *time.Time
	Batches     int
	Progress    RevertProgress
	// ChangeID is the revert's own change record (op REVERT), set once a
	// one-call revert is applied or a batched plan is signed.
	ChangeID *uuid.UUID
	// Widened is set once the person widened the revert beyond the role's
	// own work (version 20): the view then shows no binding, selection or
	// lines.
	Widened bool
	// RejectedAt and RejectNote are set on a REJECTED revert: when the
	// person rejected it, and the note they wrote for the agent ("" for
	// none).
	RejectedAt *time.Time
	RejectNote string
	// CreatedAt is when the revert was prepared.
	CreatedAt time.Time
}

// RevertProgress counts a batched plan's lines by outcome.
type RevertProgress struct {
	Restored int
	Skipped  int
	Pending  int
}

func revertSelect() sq.SelectBuilder {
	return psql.Select(colRevertID, "status", "scope", "scope_id", "intent", "rows", "skipped", "expires_at",
		"coalesce(binding_text, '')", "coalesce(lines, '{}')", "batched", "signed_at", "apply_by", "batches",
		"coalesce(restored, 0)", "coalesce(skipped_now, 0)", "coalesce(pending, 0)", "change_id", "widened",
		"rejected_at", "coalesce(reject_note, '')", "created_at").
		From("basalt_meta.agent_reverts")
}

func scanRevert(row pgx.CollectableRow) (Revert, error) {
	var r Revert
	err := row.Scan(&r.ID, &r.Status, &r.Scope, &r.ScopeID, &r.Intent, &r.Rows, &r.Skipped, &r.ExpiresAt, &r.BindingText,
		&r.Lines, &r.Batched, &r.SignedAt, &r.ApplyBy, &r.Batches,
		&r.Progress.Restored, &r.Progress.Skipped, &r.Progress.Pending, &r.ChangeID, &r.Widened,
		&r.RejectedAt, &r.RejectNote, &r.CreatedAt)
	return r, err
}

// FindRevert returns a revert the calling role prepared.
func FindRevert(ctx context.Context, q guard.Querier, id uuid.UUID) (Revert, error) {
	sql, args, err := revertSelect().Where(sq.Eq{colRevertID: id.String()}).ToSql()
	if err != nil {
		return Revert{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return Revert{}, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanRevert)
	if errors.Is(err, pgx.ErrNoRows) {
		return Revert{}, ErrRevertNotFound
	}
	return r, err
}

// RevertListParams lists the calling role's open reverts. Status "" means
// PENDING and APPLYING.
type RevertListParams struct {
	pagination.Params
	Status string
}

// colRevertID is the revert id column of basalt_meta.agent_reverts.
const colRevertID = "revert_id"

// ListOpenReverts returns one page of the calling role's reverts waiting
// for the person's signature (PENDING, not expired) or for the role's
// batches (APPLYING), keyset on the revert id as held writes are, so the
// two lists merge in one order (list_pending, LP-1).
func ListOpenReverts(ctx context.Context, q guard.Querier, p RevertListParams) (pagination.Page[Revert], error) {
	switch p.Status {
	case "", RevertPending, RevertApplying:
	default:
		return pagination.Page[Revert]{}, fmt.Errorf("%w: status %q", ErrInvalidParams, p.Status)
	}
	l := openList[Revert]{
		selectAll: revertSelect(), idColumn: colRevertID, statuses: []string{RevertPending, RevertApplying},
		scan: scanRevert, id: func(r Revert) uuid.UUID { return r.ID },
	}
	return l.page(ctx, q, p.Params, p.Status)
}

// Outcomes of a batched plan's lines.
const (
	OutcomePending  = guard.OutcomePending
	OutcomeRestored = guard.OutcomeRestored
	OutcomeSkipped  = guard.OutcomeSkipped
)

// RevertLine is one line of a batched plan: its number (execution order),
// the signed text, and what happened to it. Batch is nil while pending.
type RevertLine struct {
	No       int
	Text     string
	Outcome  string
	Conflict string
	SQLState string
	Batch    *int
}

// RevertLineParams lists a batched plan's lines in number order. Outcome
// "" lists every line.
type RevertLineParams struct {
	pagination.Params
	RevertID uuid.UUID
	Outcome  string
}

// ListRevertLines returns one page of the lines of a batched plan the
// calling role prepared, keyset on the line number.
func ListRevertLines(ctx context.Context, q guard.Querier, p RevertLineParams) (pagination.Page[RevertLine], error) {
	sql, args, err := revertLinePage(p)
	if err != nil {
		return pagination.Page[RevertLine]{}, err
	}
	return collectRevertLines(ctx, q, p, sql, args)
}

// ListRevertLinesMarked is ListRevertLines for an agent (revert_plan): each
// line's values and images too large for the agent are left out and named
// in its largeValues, and its changeIds cut to the first
// largevalue.MaxChangeIDs (CONTRACT.md, Large values).
func ListRevertLinesMarked(ctx context.Context, q guard.Querier, p RevertLineParams) (pagination.Page[RevertLine], error) {
	page, args, err := revertLinePage(p)
	if err != nil {
		return pagination.Page[RevertLine]{}, err
	}
	// Plain SQL: a recursive CTE over the page (largevalue.ElideLines).
	sql := largevalue.With + `lv_page AS MATERIALIZED (` + page + `), ` +
		largevalue.ElideLines(`SELECT line_no AS item, line::jsonb AS line FROM lv_page WHERE line <> ''`) + `
		SELECT p.line_no, coalesce(e.line::text, p.line), p.outcome, p.conflict, p.sql_state, p.batch
		FROM lv_page p LEFT JOIN lv_lines e ON e.item = p.line_no
		ORDER BY p.line_no`
	return collectRevertLines(ctx, q, p, sql, args)
}

// revertLinePage is the SQL of one page of a plan's lines, one more than
// the limit.
func revertLinePage(p RevertLineParams) (string, []any, error) {
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
	case OutcomePending, OutcomeRestored, OutcomeSkipped:
		b = b.Where(sq.Eq{"outcome": p.Outcome})
	default:
		return "", nil, fmt.Errorf("%w: outcome %q", ErrInvalidParams, p.Outcome)
	}
	b, err := pagination.ApplySeqKeyset(b, "line_no", false, p.Cursor)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return b.ToSql()
}

// collectRevertLines runs sql and returns its rows as one page of p.
func collectRevertLines(ctx context.Context, q guard.Querier, p RevertLineParams, sql string, args []any) (pagination.Page[RevertLine], error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[RevertLine]{}, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (RevertLine, error) {
		var l RevertLine
		err := row.Scan(&l.No, &l.Text, &l.Outcome, &l.Conflict, &l.SQLState, &l.Batch)
		return l, err
	})
	if err != nil {
		return pagination.Page[RevertLine]{}, err
	}
	page := pagination.Page[RevertLine]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		page.NextCursor = pagination.EncodeSeqCursor(int64(page.Items[p.Limit-1].No))
	}
	return page, nil
}
