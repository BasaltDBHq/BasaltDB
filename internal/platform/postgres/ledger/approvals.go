package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// Approval statuses (basalt_meta.agent_approvals).
const (
	ApprovalPending  = "PENDING"
	ApprovalApproved = "APPROVED"
	ApprovalApplied  = "APPLIED"
	ApprovalExpired  = "EXPIRED"
)

// ErrApprovalNotFound is an approval id that is not one of the calling
// agent's approvals.
var ErrApprovalNotFound = errors.New("approval not found")

// ApprovalSortSpec whitelists the approval list sort: by id, newest first
// by default, as change records.
var ApprovalSortSpec = ChangeSortSpec

// colApprovalID is the approval id column of basalt_meta.agent_approvals.
const colApprovalID = "approval_id"

// requestKind is the held request's family, as the binding names it
// (request.kind); empty once the binding is pruned.
const requestKind = "coalesce(binding_text::jsonb #>> '{request,kind}', '') AS request_kind"

func approvalSelect(ctx context.Context) sq.SelectBuilder {
	return withRequest(ctx, psql.Select(colApprovalID, colRunID, "task_id", "intent", requestKind, "coalesce(statement, '') AS statement", "params",
		"assigned_columns", "rows", "status", "created_at", "expires_at", "approved_at",
		"coalesce(binding_text, '') AS binding_text").
		From("basalt_meta.agent_approvals"))
}

func scanApproval(row pgx.CollectableRow) (action.Approval, error) {
	var a action.Approval
	err := row.Scan(approvalDest(&a)...)
	return a, err
}

func approvalDest(a *action.Approval) []any {
	return []any{
		&a.ID, &a.RunID, &a.TaskID, &a.Intent, &a.Request.Kind, &a.Request.Text, &a.Request.Params, &a.Assigned, &a.Rows, &a.Status,
		&a.CreatedAt, &a.ExpiresAt, &a.ApprovedAt, &a.BindingText, &a.Lines, &a.LinesLeftOut, &a.LinesCost,
	}
}

// scanMarkedApproval scans markedApprovals' row: the approval, then its
// largeValues.
func scanMarkedApproval(row pgx.CollectableRow) (action.Approval, error) {
	var a action.Approval
	var large []byte
	if err := row.Scan(append(approvalDest(&a), &large)...); err != nil {
		return action.Approval{}, err
	}
	return a, unmarshalEntries(large, &a.LargeValues)
}

// markedApprovals reads a page of approvals with a statement or params
// too large for the agent left out (CONTRACT.md, Large values: a held
// write's statement, then its params).
func markedApprovals(page string, desc bool, limit int) string {
	order := colApprovalID
	if desc {
		order += descending
	}
	return markedPage(page, colApprovalID, order, limit, "p.approval_id", "p.run_id", "p.task_id", "p.intent", "p.request_kind", markedStatement,
		markedParams, "p.assigned_columns", "p.rows", "p.status", "p.created_at", "p.expires_at", "p.approved_at",
		pageOnly("p.binding_text", "''"), pageOnly("p.lines", "'{}'::text[]"), "p.lines_left_out", "p.lines_cost", markedLarge)
}

// FindApproval returns one of the calling agent's approvals.
func FindApproval(ctx context.Context, q guard.Querier, id uuid.UUID) (action.Approval, error) {
	sql, args, err := approvalSelect(ctx).Where(sq.Eq{"approval_id": id.String()}).ToSql()
	if err != nil {
		return action.Approval{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return action.Approval{}, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return action.Approval{}, ErrApprovalNotFound
	}
	return a, err
}

// ListOpenApprovals returns one page of the calling agent's held writes that
// are waiting for the person (PENDING) or approved and not yet applied
// (APPROVED). Only list_pending reads it: a statement or params too large
// for the agent is left out and named in LargeValues.
func ListOpenApprovals(ctx context.Context, q guard.Querier, p approvalstore.ApprovalListParams) (pagination.Page[action.Approval], error) {
	switch p.Status {
	case "", ApprovalPending, ApprovalApproved:
	default:
		return pagination.Page[action.Approval]{}, fmt.Errorf("%w: status %q", ErrInvalidParams, p.Status)
	}
	b := approvalSelect(ctx)
	if p.RunID != uuid.Nil {
		b = b.Where(sq.Eq{colRunID: p.RunID.String()})
	}
	l := openList[action.Approval]{
		selectAll: b, idColumn: colApprovalID, statuses: []string{ApprovalPending, ApprovalApproved},
		scan: scanMarkedApproval, id: func(a action.Approval) uuid.UUID { return a.ID }, wrap: markedApprovals,
	}
	return l.page(ctx, q, p.Params, p.Status)
}

// maxPasskeys bounds the passkey list; a database has a handful.
const maxPasskeys = 100

// PasskeyUnusedAfter is how long a passkey may go without signing an
// approval or revert before basalt log names it (CONTRACT.md, Passkey
// management): a lost passkey is found by its silence.
const PasskeyUnusedAfter = 90 * 24 * time.Hour

// Passkey is an active passkey as the agent views show it: what a relay
// needs to check a code, its label and dates.
type Passkey struct {
	Credential passkey.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ListPasskeys returns the active passkeys (at most 100), oldest first.
func ListPasskeys(ctx context.Context, q guard.Querier) ([]Passkey, error) {
	sql, args, err := psql.Select("credential_id", "public_key_x", "public_key_y", "rp_id", "origin", "sign_count",
		"label", "created_at", "last_used_at").
		From("basalt_meta.agent_passkeys").OrderBy("created_at", "credential_id").Limit(maxPasskeys).ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Passkey, error) {
		var (
			k     Passkey
			c     = &k.Credential
			x, y  []byte
			count int64
		)
		if err := row.Scan(&c.ID, &x, &y, &c.Relying.RPID, &c.Relying.Origin, &count, &k.Label, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return k, err
		}
		pub, err := passkey.PublicKeyFromXY(x, y)
		if err != nil {
			return k, err
		}
		c.PublicKey = pub
		c.SignCount = uint32(min(max(count, 0), int64(^uint32(0))))
		return k, nil
	})
}

// Passkeys returns the active passkeys' credentials, for relays that fill
// credentialIds and check a code before submitting it.
func Passkeys(ctx context.Context, q guard.Querier) ([]passkey.Credential, error) {
	keys, err := ListPasskeys(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]passkey.Credential, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Credential)
	}
	return out, nil
}
