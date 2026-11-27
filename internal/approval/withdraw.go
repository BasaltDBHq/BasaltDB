package approval

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// WithdrawParams is a withdraw call (CONTRACT.md, MCP tools, withdraw):
// exactly one of ApprovalID (a held write or a plugin approval) and
// RevertID, with the agent's reason.
type WithdrawParams struct {
	ApprovalID uuid.UUID
	RevertID   uuid.UUID
	Reason     string
}

// WithdrawResult is withdraw's answer: the item as the store records it
// after the call, and what to tell the person.
type WithdrawResult struct {
	action.Withdrawal
	PersonMessage string
	NextSteps     []toolresult.NextStep
}

// Withdraw cases of the next steps catalog: the item is withdrawn (now or
// earlier), or it was no longer waiting and nothing changed.
const (
	WithdrawCaseWithdrawn  = "WITHDRAWN"
	WithdrawCaseNotWaiting = "NOT_WAITING"
)

// WithdrawApproval withdraws one of the agent's held writes while it waits
// for the person. found is false when the agent holds no held write with
// that id (it may be a plugin approval). The answer is the held write as the
// store records it after the call: WITHDRAWN, or the status it kept when it
// was no longer waiting. The link is never revoked: its page shows the held
// write withdrawn.
func (ac *Service) WithdrawApproval(ctx context.Context, id uuid.UUID, reason string) (action.Withdrawal, bool, error) {
	if _, err := ac.store.Records.FindApproval(ctx, id); err != nil {
		if approvalstore.IsApprovalRefused(err, approvalstore.ApprovalNotFound) {
			return action.Withdrawal{}, false, nil
		}
		return action.Withdrawal{}, true, err
	}
	if _, err := ac.store.Holds.WithdrawApproval(ctx, id, reason); err != nil {
		return action.Withdrawal{}, true, err
	}
	a, err := ac.store.Records.FindApproval(ctx, id)
	if err != nil {
		return action.Withdrawal{}, true, err
	}
	status := a.Status
	if status == action.ApprovalPending && !ac.core.Now().Before(a.ExpiresAt) {
		status = action.ApprovalExpired
	}
	return action.Withdrawal{Kind: action.WithdrawHeldWrite, ID: a.ID, Status: status, WithdrawnAt: a.WithdrawnAt, Reason: a.WithdrawReason}, true, nil
}

// WithdrawNotFound is withdraw's answer for an id the agent holds no
// waiting item for: another agent's, or none. kind is
// action.WithdrawRevert for a revertId, else the approvalId's.
func WithdrawNotFound(kind string, id uuid.UUID) *toolresult.ToolError {
	if kind == action.WithdrawRevert {
		return &toolresult.ToolError{
			Code: guidance.CodeNotFound, Reason: guidance.ReasonRevert,
			Message: fmt.Sprintf("no revert %s prepared by this agent; nothing was withdrawn", id),
		}
	}
	return &toolresult.ToolError{
		Code: guidance.CodeNotFound, Reason: guidance.ReasonApproval,
		Message: fmt.Sprintf("no held write or plugin approval %s of this agent; nothing was withdrawn", id),
	}
}

// WithdrawAnswer is what withdraw tells the agent and the person about w.
func WithdrawAnswer(w action.Withdrawal) (WithdrawResult, error) {
	b := guidance.NewSteps()
	var msg string
	if w.Withdrawn() {
		// The page says the same: its link shows it withdrawn.
		msg = guidance.WithdrawnMessage(w.Reason)
		b.Stop("Tell the person it is withdrawn. Do not ask them to sign it, and do not apply it.")
	} else {
		msg = fmt.Sprintf("%s no longer waits for your passkey (it is %s), so it was not withdrawn. Nothing changed.",
			guidance.Sentence(withdrawnWhat(w)), strings.ToLower(w.Status))
		b.Stop("Tell the person its state: it was no longer waiting, so nothing was withdrawn.")
	}
	steps, err := b.Build()
	if err != nil {
		return WithdrawResult{}, err
	}
	return WithdrawResult{Withdrawal: w, PersonMessage: msg, NextSteps: steps}, nil
}

// withdrawnWhat names the item for the person.
func withdrawnWhat(w action.Withdrawal) string {
	switch w.Kind {
	case action.WithdrawRevert:
		return "this revert"
	case action.WithdrawPluginApproval:
		if w.Name != "" {
			return "the approval of the plugin " + w.Name + "/" + w.Instance
		}
		return "this plugin approval"
	}
	return "this held write"
}
