package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// approvalNotice builds what the agent shows the person about a held
// write: its headline, the link chosen by the link budget (chooseLink: a
// newly issued short link when this engine serves the pages and issue is
// set, else the long one) and the message to show
// verbatim.
func (ac *approvalCase) approvalNotice(ctx context.Context, id, runID uuid.UUID, req sizedRequest, expires time.Time, issue bool) (heldNotice, error) {
	ids, err := ac.delivery.credentialIDs(ctx)
	if err != nil {
		return heldNotice{}, err
	}
	long, tooLarge, err := longOrTooLarge(req, func() (string, error) {
		return approval.Request{ApprovalID: id, Binding: req.Binding, Lines: req.Lines, CredentialIDs: ids}.URL(ac.core.PagesBase)
	})
	if err != nil {
		return heldNotice{}, err
	}
	// The lines' heads (a request left out) count the rows as well.
	summary, err := approval.SummarizeText(req.Lines)
	if err != nil {
		return heldNotice{}, err
	}
	if tooLarge {
		return ac.largeApprovalNotice(ctx, id, runID, req, summary, expires, issue, len(ids) == 0)
	}
	short, err := ac.delivery.shortLink(ctx, links.Approval, id, expires, issue)
	if err != nil {
		return heldNotice{}, err
	}
	pick, err := chooseLink(short, long, ac.core.LinkBudget, links.ApprovalFile(id))
	if err != nil {
		return heldNotice{}, err
	}
	reason := guidance.ReasonHeld
	lead := "Held for your approval: " + guidance.Shown(summary.Headline(), maxHeadlineChars) + "."
	var text string
	var msgLinks []toolresult.Link
	switch {
	case short == "" && ac.delivery.shortLinked(id):
		// A wait or a list that issues no new link: the link already handed
		// over still works, so the message adds no URL.
		pick = handOver{URL: long, Kind: linkLong}
		text, msgLinks = waitMessage(lead, expires)
	default:
		if short == "" {
			reason = guidance.ReasonHeldNoPages
		}
		text, msgLinks = approvalMessage(lead, pick, expiryLine(expires))
	}
	if len(ids) == 0 {
		reason = guidance.ReasonNoPasskey // nobody can sign: the first step is to register a passkey
	}
	return heldNotice{
		reason: reason,
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: guidance.TimeText(expires), Rows: len(req.Lines), Headline: summary.Headline(),
			ApprovalURL: pick.URL, RequestFile: pick.File, PersonMessage: text, Links: msgLinks,
		},
		pick:      pick,
		longURL:   long,
		shortURL:  short,
		shortHeld: ac.delivery.shortLinked(id),
	}, nil
}

// waitMessage is the personMessage of a wait or a list that issues no new
// link: the link already handed over still works.
func waitMessage(lead string, expires time.Time) (string, []toolresult.Link) {
	return pointBackMessage(lead, expiryLine(expires))
}

// pointBackMessage is lead, then a pointer to the approval link the person
// was given, then tail.
func pointBackMessage(lead string, tail ...string) (string, []toolresult.Link) {
	msg := guidance.NewMessage().Text(lead).Text("Approve with the link you were given.")
	for _, line := range tail {
		msg.Text(line)
	}
	return msg.Build()
}

// approvalRequiredError is the APPROVAL_REQUIRED answer for a new hold:
// show the link, then wait once, in the same turn.
func approvalRequiredError(n heldNotice) error {
	return approvalError(n, fmt.Sprintf("held for the person's approval: %d rows. Show the person approval.personMessage verbatim, "+
		"then, without ending your turn, call write once with the same arguments plus approvalId: it waits up to %d seconds "+
		"for their passkey and returns APPLIED as soon as they approve. %s It expires at %s.",
		n.Rows, int(DefaultApprovalWait.Seconds()), afterWaitRunsOut, n.ExpiresAt))
}

// approvalStillPendingError is the APPROVAL_REQUIRED answer of a wait
// that ran out: no second wait, the person may take long.
func approvalStillPendingError(n heldNotice) error {
	n.reason = guidance.ReasonWaitEnded
	return approvalError(n, fmt.Sprintf("still waiting for the person's approval of %d rows; nothing was applied. "+
		"Do not call write to wait again. End your turn: tell the person the write is waiting for their approval "+
		"(approval.personMessage has the link), that it expires at %s, and that you apply it when they "+
		"tell you they approved. Then call write with the same arguments plus approvalId: it applies at once.",
		n.Rows, n.ExpiresAt))
}

// afterWaitRunsOut tells the agent what to do when its one wait for a
// person's approval returns APPROVAL_REQUIRED again.
const afterWaitRunsOut = "If that call returns APPROVAL_REQUIRED again, its wait ran out: do not wait again, " +
	"end your turn as its message says."

func approvalError(n heldNotice, message string) error {
	notice := n.ApprovalNotice
	if n.reason == reasonRequestTooLarge {
		// No link can carry it: the hold has no link at all (CONTRACT.md,
		// Large values, rule 4), and the wait that ran out says the same.
		notice.ApprovalURL = ""
		return &toolresult.ToolError{
			Code: guidance.CodeApprovalRequired, Reason: reasonRequestTooLarge, Approval: &notice,
			Message: fmt.Sprintf("held for the person's approval: %d rows, but they are too large for any link this engine has "+
				"(a page decodes at most 1 MiB from a link). It stays held until it expires at %s; do not wait for it. "+
				"Do what nextSteps say.", n.Rows, n.ExpiresAt),
			PersonMessage: notice.PersonMessage, NextSteps: n.steps,
		}
	}
	return &toolresult.ToolError{
		Code: guidance.CodeApprovalRequired, Reason: n.reason, Message: message, Approval: &notice,
		PersonMessage: notice.PersonMessage, Links: notice.Links,
	}
}

// requestOf is a's request as the agent's read returned it.
func requestOf(a action.Approval) sizedRequest {
	return sizedRequest{Binding: a.BindingText, Lines: a.Lines, LeftOut: a.LinesLeftOut, Cost: max(a.LinesCost, textsCost(a.Lines))}
}

// largeApprovalNotice is approvalNotice for a request too large for a long
// link, a hash link or a request file (CONTRACT.md, Large values, rules 3
// to 5): a new short link that can carry it when issue is set and there is
// one; the page's address when a short link given earlier carries it; else
// REQUEST_TOO_LARGE.
func (ac *approvalCase) largeApprovalNotice(ctx context.Context, id, runID uuid.UUID, req sizedRequest, summary approval.Summary,
	expires time.Time, issue, noPasskey bool,
) (heldNotice, error) {
	lead := "Held for your approval: " + guidance.Shown(summary.Headline(), maxHeadlineChars) + "."
	n := heldNotice{
		reason: guidance.ReasonHeld,
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: guidance.TimeText(expires), Rows: len(req.Lines), Headline: summary.Headline(),
			ApprovalURL: ac.delivery.pageAddress(links.Approval, id),
		},
	}
	short := ""
	if issue {
		var err error
		if short, err = ac.delivery.largeShortLink(ctx, links.Approval, id, expires, req.Cost); err != nil {
			return heldNotice{}, err
		}
	}
	switch {
	case short != "":
		n.pick, n.shortURL, n.ApprovalURL = handOver{URL: short, Kind: linkShort}, short, short
		n.PersonMessage, n.Links = approvalMessage(lead, n.pick, expiryLine(expires))
	case !issue && ac.delivery.carriesLarge(req.Cost):
		// The short link handed over still works: the message points back.
		n.PersonMessage, n.Links = waitMessage(lead, expires)
	default:
		steps, err := approvalTooLargeSteps(runID)
		if err != nil {
			return heldNotice{}, err
		}
		n.reason, n.steps = reasonRequestTooLarge, steps
		n.PersonMessage = ac.delivery.tooLargeMessage("The held write", req.Cost, expires, false)
		return n, nil
	}
	n.shortHeld = ac.delivery.shortLinked(id)
	if noPasskey {
		n.reason = guidance.ReasonNoPasskey
	}
	return n, nil
}

// DefaultApprovalWait is how long a write with approvalId waits for the
// person's signature when the call does not say (CONTRACT.md, Waiting
// write), under the 2 minutes after which Claude Code moves a tool call to
// the background.
const DefaultApprovalWait = 90 * time.Second

func approvalInvalid(reason, format string, args ...any) *toolresult.ToolError {
	return &toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// differentWrite is the refusal of a write that is not the held one: its
// step repeats the held write exactly, with its approval id.
func differentWrite(a action.Approval, format string, args ...any) error {
	te := approvalInvalid(guidance.ReasonDifferentWrite, format, args...)
	call := map[string]any{"sql": a.Statement, "intent": a.Intent, guidance.ArgRunID: a.RunID.String(), guidance.ArgApprovalID: a.ID.String()}
	var params []any
	if len(a.Params) > 0 && json.Unmarshal(a.Params, &params) == nil && len(params) > 0 {
		call["params"] = params
	}
	if steps, err := guidance.NewSteps().CallTool(guidance.ToolWrite, call, "Send exactly the held write: this sql, these params and this intent, with its approvalId.").Build(); err == nil {
		te.NextSteps = steps
	}
	return te
}

// PendingItem is one open held write with what the agent hands the person.
type PendingItem struct {
	action.Approval
	Notice toolresult.ApprovalNotice
	// Restated is set when list_pending names the item's link without issuing
	// one while the engine serves the pages: the person has the short link.
	Restated bool
	// tooLargeSteps are the steps of an item whose request no link this
	// engine has can carry (REQUEST_TOO_LARGE); nil otherwise.
	tooLargeSteps []toolresult.NextStep
	// issued is set when this list_pending issued the item a new link the
	// person can still use.
	issued bool
	// PersonMessage and NextSteps say what happens next (CONTRACT.md, Next steps).
	PersonMessage string
	Links         []toolresult.Link
	NextSteps     []toolresult.NextStep
}

// approvalPoll is how often a waiting write checks for the signature.
// DefaultPoll is how often a waiting call reads whether the person signed.
const DefaultPoll = time.Second
