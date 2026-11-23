package agent

import (
	"errors"
	"fmt"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	"github.com/basaltdbhq/basaltdb/internal/handoff"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Failure maps err, raised by a call of tool with args, to the contract's
// error body (CONTRACT.md, Error codes and Next steps).
func (s *Service) Failure(tool string, args map[string]any, err error) *toolresult.ToolError {
	return s.agent.Failure(tool, args, err)
}

// UnavailableSteps: a database the engine cannot reach is retried once; the
// machine problems are the person's to fix, with the command for it.
func (s *Service) UnavailableSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	switch te.Reason {
	case guidance.ReasonDatabaseUnreachable:
		b.RepeatCall(f.Tool, nil, 0, "Try the same call once more, in case the database was only briefly busy.")
		b.AskPerson("Then tell the person the database cannot be reached and ask them to check that Postgres is running.")
		return guidance.DatabaseUnreachableMessage
	case guidance.ReasonTooManyConnections:
		b.RepeatCall(f.Tool, nil, 0, "Try the same call once more: a connection may have closed since.")
		b.AskPerson(guidance.TooManyConnectionsAsk)
		return guidance.TooManyConnectionsMessage(s.deps.Core.Commands)
	case guidance.ReasonCredentialRejected, guidance.ReasonGuardMissing, guidance.ReasonGuardOutdated:
		return guidance.FixSteps(b, s.deps.Core.Commands, te.Reason)
	case guidance.ReasonEngineUnreachable:
		return guidance.EngineUnreachableSteps(b, s.deps.Core.Commands, f.Tool)
	case guidance.ReasonSetupPending, guidance.ReasonSetupExpired:
		return s.setupSteps(b, te, f)
	case guidance.ReasonDatabaseNotConfirmed:
		var dn *guidance.DatabaseNotConfirmedError
		if !errors.As(f.Err, &dn) {
			b.Fail(errors.New("a database waiting for confirmation needs its setup and address"))
			return ""
		}
		return handoff.ConfirmDatabaseSteps(b, dn.SetupID, dn.Database)
	case guidance.ReasonPagesOff:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "Read the held writes: each has the link the person opens, since this engine serves no pages.")
		return ""
	}
	b.Fail(fmt.Errorf("UNAVAILABLE has no reason %q", te.Reason))
	return ""
}

// ApprovalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page: not signed yet, a signature the
// database refused, or a passkey it does not accept. The link in its message
// follows the link budget like the hold's; no new short link is issued here.
func (s *Service) ApprovalLinkError(te *toolresult.ToolError, n linksvc.HeldAnswer) *toolresult.ToolError {
	if n.Reason == linksvc.ReasonRequestTooLarge {
		// No link can carry it: the same message and steps as the hold's.
		te.PersonMessage, te.NextSteps = n.PersonMessage, n.Steps
		return te
	}
	b := guidance.NewSteps()
	var lead string
	switch te.Reason {
	case guidance.ReasonNotSigned:
		s.openApprovalAgain(b, n, "Open the link and approve with your passkey: the write is not approved yet.")
		lead = "The held write was not approved yet, so nothing was applied."
	case guidance.ReasonBadSignature:
		s.openApprovalAgain(b, n, "Approve again on the page; the signature did not verify.")
		lead = "The approval signature did not verify, so nothing was applied."
	case guidance.ReasonPasskeyRevoked:
		b.AgentRunCommand(s.deps.Core.Commands.Init(), guidance.PasskeyInitText)
		s.openApprovalAgain(b, n, "Then approve the held write with that passkey.")
		lead = "That passkey is not accepted here (unknown or revoked), so nothing was applied. The agent gives you a link to register the passkey you use; then approve again."
	default:
		return te
	}
	te.PersonMessage, te.Links = s.approvalAgainMessage(lead, n)
	b.EndTurn("End your turn: the person acts next.")
	steps, err := b.Build()
	if err != nil {
		s.deps.Core.Log.Error("cannot build approval steps", "reason", te.Reason, "err", err)
		return te
	}
	te.NextSteps = steps
	return te
}

// openApprovalAgain sends the person back to the approval page the hold
// handed over. With the pages served that is the short link they have, which
// the engine no longer holds: the step names no url, and no long link over
// the budget is handed over (CONTRACT.md, The request file and pasted
// blocks). Otherwise it is the link the hold chose: the long link within the
// budget, or the hash link, whose request file the agent already sent.
func (s *Service) openApprovalAgain(b *guidance.Steps, n linksvc.HeldAnswer, text string) {
	if n.ShortHeld || linksvc.IsPageAddress(n.ApprovalURL) {
		b.OpenGivenLink("Open the short link the agent gave you earlier. " + text)
		return
	}
	b.OpenLink(n.ApprovalURL, text)
}

// approvalAgainMessage is the personMessage of an APPROVAL_INVALID that sends
// the person back to the page: a pointer to the short link they have while
// the pages are served, else the hold's link (a hash link names the request
// file the agent already sent).
func (s *Service) approvalAgainMessage(lead string, n linksvc.HeldAnswer) (string, []toolresult.Link) {
	if n.ShortHeld {
		return approvalsvc.PointBackMessage(lead)
	}
	return linksvc.ApprovalMessage(lead, linksvc.HandOver{URL: n.Pick.URL, Kind: n.Pick.Kind, File: n.Pick.File, Sent: true})
}

// setupSteps: a pending setup is run by the person on their own computer;
// an expired one is renewed on the engine's machine (an OPERATOR step).
func (s *Service) setupSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	if te.Reason == guidance.ReasonSetupExpired {
		return guidance.SetupExpiredSteps(b, s.deps.Core.Commands)
	}
	var se *guidance.SetupError
	if !errors.As(f.Err, &se) {
		b.Fail(errors.New("a pending setup needs its code"))
		return ""
	}
	if se.ConnectOnly {
		b.CallTool(guidance.ToolStatus, map[string]any{}, "Call status: its setup problem says what the person or you do next.")
		return ""
	}
	person, ls := guidance.SetupPendingSteps(b, s.deps.Core.Commands, se.Code, se.Fingerprint, true, s.deps.Status.ConnectBudget)
	te.Links = ls
	return person
}
