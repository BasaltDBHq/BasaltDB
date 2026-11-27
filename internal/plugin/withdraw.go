package plugin

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// WithdrawPluginApproval withdraws a plugin approval the agent opened with
// request_plugin while it waits for the person (CONTRACT.md, Approvals,
// Withdrawn requests). found is false when the agent's role did not open an
// approval with that id: one that only names the agent is another agent's
// to withdraw. The answer is the approval as the guard records it after the
// call: WITHDRAWN, or the status it kept when it was no longer waiting.
func (pc *Service) WithdrawPluginApproval(ctx context.Context, id uuid.UUID, reason string) (action.Withdrawal, bool, error) {
	if pc.deps.Approvals == nil {
		return action.Withdrawal{}, false, nil
	}
	r, found, err := pc.deps.Approvals.ReadPluginApproval(ctx, id)
	// Only the opener reads the binding text (guardmodel.PluginApprovalRecord).
	if err != nil || !found || r.BindingText == "" {
		return action.Withdrawal{}, err != nil, err
	}
	if _, err := pc.deps.Approvals.WithdrawPluginApproval(ctx, id, reason); err != nil {
		return action.Withdrawal{}, true, err
	}
	r, found, err = pc.deps.Approvals.ReadPluginApproval(ctx, id)
	if err != nil || !found {
		return action.Withdrawal{}, true, err
	}
	status := string(r.Status)
	switch {
	case r.Status == guardmodel.PluginApprovalStatusPending && !pc.core.Now().Before(r.ExpiresAt):
		status = string(guardmodel.PluginApprovalStatusExpired)
	case r.Status == guardmodel.PluginApprovalStatusApproved && r.Ended():
		status = PluginStateEnded
	}
	return action.Withdrawal{
		Kind: action.WithdrawPluginApproval, ID: r.ApprovalID, Status: status, WithdrawnAt: r.WithdrawnAt, Reason: r.WithdrawReason,
		Name: r.Name, Instance: r.Instance,
	}, true, nil
}
