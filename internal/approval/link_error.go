package approval

import (
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page: not signed yet, a signature the
// database refused, or a passkey it does not accept. The link in its message
// follows the link budget like the hold's; no new short link is issued here.
func (ac *Service) ApprovalLinkError(te *toolresult.ToolError, n linksvc.HeldAnswer) *toolresult.ToolError {
	if n.Reason == linksvc.ReasonRequestTooLarge {
		// No link can carry it: the same message and steps as the hold's.
		te.PersonMessage, te.NextSteps = n.PersonMessage, n.Steps
		return te
	}
	b := guidance.NewSteps()
	var lead string
	switch te.Reason {
	case guidance.ReasonNotSigned:
		openApprovalAgain(b, n, "Open the link and approve with your passkey: the write is not approved yet.")
		lead = "The held write was not approved yet, so nothing was applied."
	case guidance.ReasonBadSignature:
		openApprovalAgain(b, n, "Approve again on the page; the signature did not verify.")
		lead = "The approval signature did not verify, so nothing was applied."
	case guidance.ReasonPasskeyRevoked:
		b.AgentRunCommand(ac.core.Commands.Init(), guidance.PasskeyInitText)
		openApprovalAgain(b, n, "Then approve the held write with that passkey.")
		lead = "That passkey is not accepted here (unknown or revoked), so nothing was applied. The agent gives you a link to register the passkey you use; then approve again."
	default:
		return te
	}
	te.PersonMessage, te.Links = approvalAgainMessage(lead, n)
	b.EndTurn("End your turn: the person acts next.")
	steps, err := b.Build()
	if err != nil {
		ac.core.Log.Error("cannot build approval steps", "reason", te.Reason, "err", err)
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
func openApprovalAgain(b *guidance.Steps, n linksvc.HeldAnswer, text string) {
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
func approvalAgainMessage(lead string, n linksvc.HeldAnswer) (string, []toolresult.Link) {
	if n.ShortHeld {
		return PointBackMessage(lead)
	}
	return linksvc.ApprovalMessage(lead, linksvc.HandOver{URL: n.Pick.URL, Kind: n.Pick.Kind, File: n.Pick.File, Sent: true})
}
