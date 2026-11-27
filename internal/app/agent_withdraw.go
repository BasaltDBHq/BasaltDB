package app

import (
	"context"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
)

// withdrawals is the withdraw tool's use case: the approval use case, with
// the plugin use case for a plugin approval's id.
type withdrawals struct{ svc *Service }

// Withdraw is the approval use case's Withdraw.
func (w withdrawals) Withdraw(ctx context.Context, p approvalsvc.WithdrawParams) (approvalsvc.WithdrawResult, error) {
	return w.svc.approval.Withdraw(ctx, p, w.svc.plugin)
}
