package agent

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// NoticeKind is why an approval.deliver notice is made (CONTRACT.md,
// Notifier messages).
type NoticeKind string

const (
	// NoticeApprovalRequested: write held a write.
	NoticeApprovalRequested NoticeKind = "APPROVAL_REQUESTED"
	// NoticeRevertRequested: request_revert prepared a revert.
	NoticeRevertRequested NoticeKind = "REVERT_REQUESTED"
	// NoticeLinkReplaced: the agent asked for a new link and one was issued.
	NoticeLinkReplaced NoticeKind = "LINK_REPLACED"
)

// LinkNotice is what an approval.deliver plugin may be told about one
// answer of this agent: the item, its headline, its expiry, and the link
// that answer handed over. It has no field for an intent, a statement, a
// parameter or a row, so none can reach a plugin through it.
type LinkNotice struct {
	Kind NoticeKind
	// ApprovalID or RevertID names the item: exactly one is set.
	ApprovalID uuid.UUID
	RevertID   uuid.UUID
	// Headline is the item's headline in the notice's form (NoticeHeadline).
	Headline  string
	ExpiresAt time.Time
	// Link is the link in the agent's answer, byte for byte, when that
	// link stands alone (a short link or a long link); "" when the answer
	// had none that does (a hash link, a page address, no link).
	Link string
}

// LinkDeliverer takes the notice of an answer the agent is about to get, or
// of a write just held whose call waits for the person. DeliverLink must
// return at once: it runs on the agent's call, after the answer that holds
// the link is built, and nothing it does may delay or change the call's
// answer. It returns nothing, so the answer cannot depend on it.
type LinkDeliverer interface {
	DeliverLink(n LinkNotice)
}

// noticeHeadlineMax is deliver.schema.json's longest headline.
const noticeHeadlineMax = 1000

// NoticeHeadline is an item's headline as a notice carries it (CONTRACT.md,
// Notifier messages, The headline): the rule for text from the agent or the
// database applied to the whole of it, then cut to 999 characters and an
// ellipsis when longer than 1,000.
func NoticeHeadline(headline string) string {
	s := guidance.PlainText(headline)
	if r := []rune(s); len(r) > noticeHeadlineMax {
		s = string(r[:noticeHeadlineMax-1]) + "…"
	}
	return s
}

// standaloneLink is link when it is a link a person can open with nothing
// beside it: a short link (#s=) or a long link (#2.). A hash link (#h=),
// whose request travels beside it, and a page address with no fragment are
// not.
func standaloneLink(link string) string {
	_, fragment, ok := strings.Cut(link, "#")
	if ok && (strings.HasPrefix(fragment, "s=") || strings.HasPrefix(fragment, "2.")) {
		return link
	}
	return ""
}

// deliver hands n to the deliverer. It is called only where the link is
// final: the agent's answer is built, or the write is held and waits, and
// nothing after it issues another link for the item in this call. A
// deliverer that panics is logged and costs the agent nothing: the answer
// is returned as it was built.
func (s *Service) deliver(n LinkNotice) {
	if s.deps.Delivery.Deliverer == nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			s.deps.Core.Log.Error("approval notice not made: the deliverer panicked", "kind", string(n.Kind))
		}
	}()
	n.Headline = NoticeHeadline(n.Headline)
	n.Link = standaloneLink(n.Link)
	if n.Headline == "" || n.ExpiresAt.IsZero() || (n.ApprovalID == uuid.Nil) == (n.RevertID == uuid.Nil) {
		return
	}
	s.deps.Delivery.Deliverer.DeliverLink(n)
}

// deliverHeld makes the notice of answer, the APPROVAL_REQUIRED answer of
// a write this call held: its link is that answer's approval.approvalUrl.
// Write calls it once, when the write is held, also when the call then
// waits for the person.
func (s *Service) deliverHeld(id uuid.UUID, expires time.Time, answer error) {
	var te *toolresult.ToolError
	if !errors.As(answer, &te) || te.Code != guidance.CodeApprovalRequired || te.Approval == nil {
		return
	}
	s.deliver(LinkNotice{
		Kind: NoticeApprovalRequested, ApprovalID: id, Headline: te.Approval.Headline, ExpiresAt: expires, Link: te.Approval.ApprovalURL,
	})
}
