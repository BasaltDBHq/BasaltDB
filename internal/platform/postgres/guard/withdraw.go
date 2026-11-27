package guard

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// WithdrawApproval withdraws the caller's own held write while it waits for
// the person (basalt_meta.withdraw_approval, version 15), with the agent's
// reason. It returns when it was withdrawn, or nil for a held write no
// longer waiting (signed, applied, expired or withdrawn), left as it is.
// Another role's approval, or none, is APPROVAL_INVALID detail
// NoSuchApproval.
func WithdrawApproval(ctx context.Context, q Querier, approvalID uuid.UUID, reason string) (*time.Time, error) {
	return withdraw(ctx, q, "withdraw_approval", approvalID, reason)
}

// WithdrawRevert withdraws the caller's own revert while it waits for the
// person's signature (basalt_meta.withdraw_revert, version 15). It returns
// when it was withdrawn, or nil for a revert no longer waiting. Another
// role's revert, or none, is REVERT_INVALID detail RevertNotFound.
func WithdrawRevert(ctx context.Context, q Querier, revertID uuid.UUID, reason string) (*time.Time, error) {
	return withdraw(ctx, q, "withdraw_revert", revertID, reason)
}

// WithdrawPluginApproval withdraws a pending plugin approval the caller
// opened (basalt_meta.withdraw_plugin_approval, version 15). It returns when
// it was withdrawn, or nil for one no longer waiting. An approval the role
// did not open, or none, is APPROVAL_INVALID detail DetailApprovalNotFound.
func WithdrawPluginApproval(ctx context.Context, q Querier, approvalID uuid.UUID, reason string) (*time.Time, error) {
	return withdraw(ctx, q, "withdraw_plugin_approval", approvalID, reason)
}

// withdraw calls the withdraw function fn of the guard for id.
func withdraw(ctx context.Context, q Querier, fn string, id uuid.UUID, reason string) (*time.Time, error) {
	sql, args, err := sqlport.Builder.Select().Column(sq.Expr("basalt_meta."+fn+"(?::uuid, ?::text)", id.String(), reason)).ToSql()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn, err)
	}
	var at *time.Time
	if err := q.QueryRow(ctx, sql, args...).Scan(&at); err != nil {
		return nil, err
	}
	return at, nil
}
