package app

import (
	"context"

	"github.com/google/uuid"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// withdrawals is the withdraw tool's use case across the three kinds it
// takes (CONTRACT.md, MCP tools, withdraw): a revertId is a revert, an
// approvalId a held write, else a plugin approval the agent opened.
type withdrawals struct{ svc *Service }

// Withdraw withdraws the agent's own item named in p while it waits for the
// person, and answers its state after the call.
func (w withdrawals) Withdraw(ctx context.Context, p approvalsvc.WithdrawParams) (approvalsvc.WithdrawResult, error) {
	var (
		out   action.Withdrawal
		found bool
		err   error
	)
	if p.RevertID != uuid.Nil {
		out, found, err = w.svc.revert.WithdrawRevert(ctx, p.RevertID, p.Reason)
		if err == nil && !found {
			return approvalsvc.WithdrawResult{}, approvalsvc.WithdrawNotFound(action.WithdrawRevert, p.RevertID)
		}
	} else {
		out, found, err = w.svc.approval.WithdrawApproval(ctx, p.ApprovalID, p.Reason)
		if err == nil && !found && w.svc.plugin != nil {
			out, found, err = w.svc.plugin.WithdrawPluginApproval(ctx, p.ApprovalID, p.Reason)
		}
		if err == nil && !found {
			return approvalsvc.WithdrawResult{}, approvalsvc.WithdrawNotFound(action.WithdrawHeldWrite, p.ApprovalID)
		}
	}
	if err != nil {
		return approvalsvc.WithdrawResult{}, err
	}
	return approvalsvc.WithdrawAnswer(out)
}
