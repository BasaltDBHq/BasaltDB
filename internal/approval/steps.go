package approval

import (
	"fmt"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalRequiredSteps are APPROVAL_REQUIRED's steps, by reason: the link,
// the wait, and what to do when nobody can approve yet. It returns the
// person's message the notice carries.
func (ac *Service) ApprovalRequiredSteps(b *guidance.Steps, te *toolresult.ToolError) string {
	n := te.Approval
	if n == nil {
		b.Fail(fmt.Errorf("APPROVAL_REQUIRED carries no approval"))
		return ""
	}
	again := map[string]any{guidance.ArgApprovalID: n.ApprovalID}
	b.SendRequest(n.RequestFile)
	switch te.Reason {
	case guidance.ReasonHeld:
		b.OpenLink(n.ApprovalURL, "Open the link, review the rows and approve with your passkey.")
		b.RepeatCall(guidance.ToolWrite, again, 0, fmt.Sprintf("In this turn, call write again with the same arguments plus approvalId: it waits up to %d seconds for the approval.", int(guidance.DefaultApprovalWait.Seconds())))
	case guidance.ReasonHeldNoPages:
		// No page can sign this link (no local pages, no live Vault
		// connection): a wait cannot succeed.
		b.OpenLink(n.ApprovalURL, "Open the link to review the rows. It cannot be signed yet.")
		b.EndTurn("Do not wait: this link cannot be signed. End your turn, showing approval.personMessage.")
		b.CallTool(guidance.ToolListPending, map[string]any{linksvc.ArgReissueLink: true}, "Once status shows the Vault connected, call this for a link the person can sign, and show it.")
	case guidance.ReasonNoPasskey:
		b.AgentRunCommand(ac.core.Commands.Init(), "Nobody can approve yet: run this once and show the person the link it prints, where they register a passkey.")
		if ac.core.Commands.AgentOperated() {
			// The person registers a portal passkey on the connect page,
			// and the agent follows what init prints (RI-6).
			break
		}
		b.OpenLink(n.ApprovalURL, "Then open the link and approve the held write.")
		b.EndTurn("End your turn: the person acts next.")
	case guidance.ReasonWaitEnded:
		ac.openHeldLink(b, n, "Open the link to review the rows. It cannot be signed yet: ask the agent for a new link later.")
		b.TellAgent("Tell the agent when you have approved.")
		b.EndTurn("Do not wait again: end your turn, showing personMessage.")
		b.RepeatCall(guidance.ToolWrite, map[string]any{guidance.ArgApprovalID: n.ApprovalID, guidance.ArgWaitApproval: 0}, 0,
			"When the person says they approved, call write again with the same arguments plus approvalId: it applies at once.")
	}
	return n.PersonMessage
}

// ApprovalInvalidSteps: what the agent does depends on why the guard
// refused the approval. The three that need the approval page (NOT_SIGNED,
// BAD_SIGNATURE, PASSKEY_REVOKED) are built with its link by
// approvalLinkError.
func ApprovalInvalidSteps(b *guidance.Steps, te *toolresult.ToolError, runID string) string {
	switch te.Reason {
	case guidance.ReasonAlreadyUsed:
		b.CallTool(guidance.ToolRunHistory, runArgs(runID), "Read the run's history: the write was already applied.")
		b.Stop("Do not apply it again.")
	case guidance.ReasonDifferentWrite:
		b.CallTool(guidance.ToolListPending, runArgs(runID), "List the held write, then send exactly the held request and intent with its approvalId.")
	case guidance.ReasonNotThisAgent:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "List your pending approvals and use the approvalId of the one this write was held for.")
	case guidance.ReasonWithdrawn:
		b.Stop("Do not apply it: the held write was withdrawn and writes nothing.")
		return guidance.WithdrawnMessage("")
	case guidance.ReasonRowsChanged:
		b.ReviseCall(guidance.ToolQuery, nil, "Read the rows again to see what changed since the person was asked.")
		b.ReviseCall(guidance.ToolWrite, nil, "Send the write again with the new rows in mind: it is held anew for approval.")
		return "Rows changed after you were asked, so that approval no longer applies and nothing was written. The agent reads the rows again and the write is held anew for you."
	default:
		b.Fail(fmt.Errorf("APPROVAL_INVALID %s needs the approval page's link", te.Reason))
	}
	return ""
}

func runArgs(id string) map[string]any {
	if id != "" {
		return map[string]any{guidance.ArgRunID: id}
	}
	return map[string]any{}
}
