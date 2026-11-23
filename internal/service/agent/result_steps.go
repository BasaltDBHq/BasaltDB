package agent

import (
	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// itemGuidance is the steps and the person's message for one list_pending
// item (CONTRACT.md, Next steps): a write waiting for the person's passkey,
// or one that expired meanwhile. An approved item needs nothing from the
// person, and the agent applies it as the tool says.
func (s *Service) itemGuidance(p PendingItem) (string, []toolresult.Link, []toolresult.NextStep, error) {
	switch {
	case s.expired(p):
		b := guidance.NewSteps()
		guidance.ApprovalExpiredSteps(b)
		steps, err := b.Build()
		return approvalExpiredMessage, nil, steps, err
	case s.waitsForPerson(p) && p.tooLargeSteps != nil:
		return p.Notice.PersonMessage, nil, p.tooLargeSteps, nil
	case s.waitsForPerson(p):
		b := guidance.NewSteps().SendRequest(p.Notice.RequestFile)
		openItemLink(b, p)
		steps, err := b.Build()
		return p.Notice.PersonMessage, p.Notice.Links, steps, err
	}
	return p.Notice.PersonMessage, p.Notice.Links, nil, nil
}

// openItemLink adds a pending item's OPEN_LINK step: with no url when
// list_pending restates the link while the engine serves the pages.
func openItemLink(b *guidance.Steps, p PendingItem) {
	if p.Restated {
		b.OpenGivenLink("Open the link the agent gave you earlier, review the rows and approve with your passkey.")
		return
	}
	b.OpenLink(p.Notice.ApprovalURL, "Open the link, review the rows and approve with your passkey.")
}

// openHeldLink adds the person's OPEN_LINK step after a wait that ran out:
// with no url while the engine serves the pages (the person has the short
// link the hold handed over; CONTRACT.md, The request file and pasted
// blocks), else at the link the hold handed over.
func (s *Service) openHeldLink(b *guidance.Steps, n *toolresult.ApprovalNotice, text string) {
	if id, err := uuid.Parse(n.ApprovalID); (err == nil && s.delivery.shortLinked(id)) || isPageAddress(n.ApprovalURL) {
		b.OpenGivenLink("Open the short link the agent gave you earlier and approve with your passkey.")
		return
	}
	b.OpenLink(n.ApprovalURL, text)
}

// expired reports whether a held write ran out before it was approved.
func (s *Service) expired(p PendingItem) bool {
	return p.Status == approvalExpired || !s.deps.Core.Now().Before(p.ExpiresAt)
}

// waitsForPerson reports whether a held write still waits for the person's
// passkey: only then does it need its request sent.
func (s *Service) waitsForPerson(p PendingItem) bool {
	return p.Status == approvalPending && !s.expired(p)
}

const approvalExpiredMessage = "The held write expired before it was approved, so nothing was applied. Ask the agent to send it again if you still want it."
