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
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
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

// Approval is one of the calling agent's held writes.
type Approval struct {
	ID          uuid.UUID
	RunID       uuid.UUID
	TaskID      uuid.NullUUID
	Intent      string
	Statement   string
	Params      json.RawMessage
	Assigned    []string
	Rows        int
	Status      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ApprovedAt  *time.Time
	BindingText string
	Lines       []string
}

// ApprovalSortSpec whitelists the approval list sort: by id, newest first
// by default, as change records.
var ApprovalSortSpec = ChangeSortSpec

// ApprovalListParams lists held writes that can still be approved or
// applied. RunID uuid.Nil means every run; Status "" means PENDING and
// APPROVED.
type ApprovalListParams struct {
	pagination.Params
	RunID  uuid.UUID
	Status string
}

func approvalSelect() sq.SelectBuilder {
	return psql.Select("approval_id", "run_id", "task_id", "intent", "coalesce(statement, '')", "params",
		"assigned_columns", "rows", "status", "created_at", "expires_at", "approved_at",
		"coalesce(binding_text, '')", "coalesce(lines, '{}')").
		From("basalt_meta.agent_approvals")
}

func scanApproval(row pgx.CollectableRow) (Approval, error) {
	var a Approval
	err := row.Scan(&a.ID, &a.RunID, &a.TaskID, &a.Intent, &a.Statement, &a.Params, &a.Assigned, &a.Rows, &a.Status,
		&a.CreatedAt, &a.ExpiresAt, &a.ApprovedAt, &a.BindingText, &a.Lines)
	return a, err
}

// FindApproval returns one of the calling agent's approvals.
func FindApproval(ctx context.Context, q guard.Querier, id uuid.UUID) (Approval, error) {
	sql, args, err := approvalSelect().Where(sq.Eq{"approval_id": id.String()}).ToSql()
	if err != nil {
		return Approval{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return Approval{}, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrApprovalNotFound
	}
	return a, err
}

// ListOpenApprovals returns one page of the calling agent's held writes that
// are waiting for the person (PENDING) or approved and not yet applied
// (APPROVED).
func ListOpenApprovals(ctx context.Context, q guard.Querier, p ApprovalListParams) (pagination.Page[Approval], error) {
	if p.Limit < 1 || p.Limit > pagination.MaxLimit {
		return pagination.Page[Approval]{}, fmt.Errorf("%w: limit %d", ErrInvalidParams, p.Limit)
	}
	sort, err := p.ParseSort(ApprovalSortSpec)
	if err != nil {
		return pagination.Page[Approval]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	order := "approval_id"
	if sort.Desc {
		order += " DESC"
	}
	statuses := []string{ApprovalPending, ApprovalApproved}
	switch p.Status {
	case "":
	case ApprovalPending, ApprovalApproved:
		statuses = []string{p.Status}
	default:
		return pagination.Page[Approval]{}, fmt.Errorf("%w: status %q", ErrInvalidParams, p.Status)
	}
	b := approvalSelect().Where(sq.Eq{"status": statuses}).OrderBy(order).Limit(uint64(p.Limit) + 1)
	if p.RunID != uuid.Nil {
		b = b.Where(sq.Eq{"run_id": p.RunID.String()})
	}
	b, err = pagination.ApplyIDKeyset(b, "approval_id", sort.Desc, p.Cursor)
	if err != nil {
		return pagination.Page[Approval]{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	sql, args, err := b.ToSql()
	if err != nil {
		return pagination.Page[Approval]{}, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return pagination.Page[Approval]{}, err
	}
	items, err := pgx.CollectRows(rows, scanApproval)
	if err != nil {
		return pagination.Page[Approval]{}, err
	}
	page := pagination.Page[Approval]{Items: items}
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		page.NextCursor = pagination.EncodeIDCursor(page.Items[p.Limit-1].ID.String())
	}
	return page, nil
}

// maxPasskeys bounds the passkey list; a database has a handful.
const maxPasskeys = 100

// Passkeys returns the registered passkeys' public data, as stored.
func Passkeys(ctx context.Context, q guard.Querier) ([]passkey.Credential, error) {
	sql, args, err := psql.Select("credential_id", "public_key_x", "public_key_y", "rp_id", "origin", "sign_count").
		From("basalt_meta.agent_passkeys").OrderBy("credential_id").Limit(maxPasskeys).ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (passkey.Credential, error) {
		var (
			c     passkey.Credential
			x, y  []byte
			count int64
		)
		if err := row.Scan(&c.ID, &x, &y, &c.Relying.RPID, &c.Relying.Origin, &count); err != nil {
			return c, err
		}
		pub, err := passkey.PublicKeyFromXY(x, y)
		if err != nil {
			return c, err
		}
		c.PublicKey = pub
		c.SignCount = uint32(min(max(count, 0), int64(^uint32(0))))
		return c, nil
	})
}
