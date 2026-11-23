package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// HeldNotice is a held write to tell the person about.
type HeldNotice struct {
	ApprovalID uuid.UUID
	Agent      string
	Intent     string
	Statement  string
	Rows       int
	// Headline states what the write changes, cascades explicit
	// (approval.Summary.Headline).
	Headline    string
	ExpiresAt   time.Time
	ApprovalURL string
	// ShortURL is the short link with its secret, when the engine serves
	// the pages; it works on the engine's machine only.
	ShortURL string
}

// RevertNotice is a revert waiting for the person's signature, to tell
// them about when the agent requests it or has its link issued again
// (owner decision LP-2).
type RevertNotice struct {
	RevertID uuid.UUID
	Agent    string
	// Headline is built from what Postgres returned (revertHeadline).
	Headline  string
	Intent    string
	ExpiresAt time.Time
	// RevertURL is the long link, ShortURL the short one when the engine
	// serves the pages. Both are empty for a widened revert, whose notice
	// carries only the headline (LP-3).
	RevertURL string
	ShortURL  string
	Widened   bool
}

// Notifier tells the person a write is held or a revert waits for them.
// The engine has no notifier today, so it is noNotifier; it is the seam a
// notification channel plugs into later. It only delivers the link;
// approving and signing need the person's passkey.
type Notifier interface {
	NotifyHeld(ctx context.Context, n HeldNotice) error
	NotifyRevert(ctx context.Context, n RevertNotice) error
}

// noNotifier is the Notifier when none is configured.
type noNotifier struct{}

func (noNotifier) NotifyHeld(context.Context, HeldNotice) error     { return nil }
func (noNotifier) NotifyRevert(context.Context, RevertNotice) error { return nil }

// hold turns a write the guard held into a held action (decision M2-1):
// refuse it when it is not repeatable, preview it in a transaction that
// rolls back, store it with its lines, notify the person, and answer
// APPROVAL_REQUIRED with the approval link. It returns the held write's
// approval id and expiry with the APPROVAL_REQUIRED error, or uuid.Nil and
// the error that kept it from being held.
func (s *Service) hold(ctx context.Context, in action.Intent, p WriteParams, stmt action.Statement, start time.Time) (uuid.UUID, time.Time, error) {
	assigned, err := s.Store.HoldColumns(ctx, p.SQL, p.Params)
	var notRepeatable *action.RefusalError
	if errors.As(err, &notRepeatable) {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	lines, err := s.Store.Preview(ctx, in, p.SQL, p.Params, assigned)
	if err != nil {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if len(lines) == 0 {
		// The rows went away between the attempt and the preview.
		return uuid.Nil, time.Time{}, &toolresult.ToolError{Code: CodeSQLError, Reason: reasonNoRowsNow, Message: "the write changes no rows now; read again and decide"}
	}
	if te := holdTooLarge(lines, nil); te != nil {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, te)
	}
	held, err := s.Store.Hold(ctx, in, action.HoldRequest{Statement: p.SQL, Params: p.Params, Assigned: assigned, Lines: lines})
	if err != nil {
		if te := holdTooLarge(lines, err); te != nil {
			return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, te)
		}
		return uuid.Nil, time.Time{}, err
	}
	req := sizedRequest{Binding: held.BindingText, Lines: lines, Cost: textsCost(lines)}
	notice, err := s.approvalNotice(ctx, held.ApprovalID, in.RunID, req, held.ExpiresAt, issueLink)
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	// The notice carries the long link, which works anywhere, and the
	// short one, which works only on this machine (CONTRACT.md, Link
	// secrets).
	sent := HeldNotice{
		ApprovalID: held.ApprovalID, Agent: s.Name, Intent: p.Intent, Statement: p.SQL,
		Rows: len(lines), Headline: notice.Headline, ExpiresAt: held.ExpiresAt, ApprovalURL: notice.longURL,
		ShortURL: notice.shortURL,
	}
	if err := s.Notifier.NotifyHeld(context.WithoutCancel(ctx), sent); err != nil {
		s.Log.Error("notify held write", "approvalId", held.ApprovalID, "err", err)
	}
	return held.ApprovalID, held.ExpiresAt, approvalRequiredError(notice)
}

// heldNotice is a held write as the agent hands it to the person
// (CONTRACT.md, Handing a held action to the person), with the long link
// for notifications.
type heldNotice struct {
	toolresult.ApprovalNotice
	// pick is the link handed over, as chooseLink chose it (the long link
	// when a wait or a list only restates it while the engine serves the pages).
	pick     handOver
	longURL  string
	shortURL string // "" when no short link was issued
	// shortHeld is set when the person holds a short link to the item that
	// still works (shortLinked): a restating result points back to it.
	shortHeld bool
	// reason is the APPROVAL_REQUIRED case: HELD, HELD_NO_PAGES, NO_PASSKEY
	// or REQUEST_TOO_LARGE (WAIT_ENDED is set by the wait that ran out).
	reason string
	// steps are the next steps of a REQUEST_TOO_LARGE notice, built where
	// the run is known; nil otherwise.
	steps []toolresult.NextStep
}

// Whether building a notice issues a new short link, revoking the item's
// earlier one (CONTRACT.md, Link secrets).
const (
	issueLink = true
	keepLink  = false
)

// approvalNotice builds what the agent shows the person about a held
// write: its headline, the link chosen by the link budget (chooseLink: a
// newly issued short link when this engine serves the pages and issue is
// set, else the long one) and the message to show
// verbatim.
func (s *Service) approvalNotice(ctx context.Context, id, runID uuid.UUID, req sizedRequest, expires time.Time, issue bool) (heldNotice, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return heldNotice{}, err
	}
	long, tooLarge, err := longOrTooLarge(req, func() (string, error) {
		return approval.Request{ApprovalID: id, Binding: req.Binding, Lines: req.Lines, CredentialIDs: ids}.URL(s.PagesBase)
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
		return s.largeApprovalNotice(ctx, id, runID, req, summary, expires, issue, len(ids) == 0)
	}
	short, err := s.shortLink(ctx, links.Approval, id, expires, issue)
	if err != nil {
		return heldNotice{}, err
	}
	pick, err := chooseLink(short, long, s.LinkBudget, links.ApprovalFile(id))
	if err != nil {
		return heldNotice{}, err
	}
	reason := reasonHeld
	lead := "Held for your approval: " + shown(summary.Headline(), maxHeadlineChars) + "."
	var text string
	var msgLinks []toolresult.Link
	switch {
	case short == "" && s.shortLinked(id):
		// A wait or a list that issues no new link: the link already handed
		// over still works, so the message adds no URL.
		pick = handOver{URL: long, Kind: linkLong}
		text, msgLinks = waitMessage(lead, expires)
	default:
		if short == "" {
			reason = reasonHeldNoPages
		}
		text, msgLinks = approvalMessage(lead, pick, expiryLine(expires))
	}
	if len(ids) == 0 {
		reason = reasonNoPasskey // nobody can sign: the first step is to register a passkey
	}
	return heldNotice{
		reason: reason,
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: timeText(expires), Rows: len(req.Lines), Headline: summary.Headline(),
			ApprovalURL: pick.URL, RequestFile: pick.File, PersonMessage: text, Links: msgLinks,
		},
		pick:      pick,
		longURL:   long,
		shortURL:  short,
		shortHeld: s.shortLinked(id),
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
	msg := newMessage().Text(lead).Text("Approve with the link you were given.")
	for _, line := range tail {
		msg.Text(line)
	}
	return msg.Build()
}

// personTime is how a person-facing message states a deadline.
const personTime = "2006-01-02 15:04 UTC"

// shortLink issues a new short link page(origin, id)#s=<secret> for an
// item that expires at expires, revoking its earlier one, when issue is
// set: the portal's short link when the Vault registered it (relayLink),
// else one to the pages this engine
// serves; else "", and the caller hands over the long link.
func (s *Service) shortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error) {
	if !issue {
		return "", nil
	}
	if link := s.relayLink(ctx, page, id, expires); link != "" {
		return link, nil
	}
	return s.localLink(page, id, expires)
}

// localLink issues a new short link to the pages this engine serves,
// revoking the item's earlier link; "" when it serves none.
func (s *Service) localLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error) {
	if s.PagesOrigin == "" {
		return "", nil
	}
	secret, err := s.Links.Issue(id, expires)
	if err != nil {
		return "", err
	}
	return links.WithSecret(page(s.PagesOrigin, id), secret), nil
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
	n.reason = reasonWaitEnded
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
			Code: CodeApprovalRequired, Reason: reasonRequestTooLarge, Approval: &notice,
			Message: fmt.Sprintf("held for the person's approval: %d rows, but they are too large for any link this engine has "+
				"(a page decodes at most 1 MiB from a link). It stays held until it expires at %s; do not wait for it. "+
				"Do what nextSteps say.", n.Rows, n.ExpiresAt),
			PersonMessage: notice.PersonMessage, NextSteps: n.steps,
		}
	}
	return &toolresult.ToolError{
		Code: CodeApprovalRequired, Reason: n.reason, Message: message, Approval: &notice,
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
func (s *Service) largeApprovalNotice(ctx context.Context, id, runID uuid.UUID, req sizedRequest, summary approval.Summary,
	expires time.Time, issue, noPasskey bool,
) (heldNotice, error) {
	lead := "Held for your approval: " + shown(summary.Headline(), maxHeadlineChars) + "."
	n := heldNotice{
		reason: reasonHeld,
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: timeText(expires), Rows: len(req.Lines), Headline: summary.Headline(),
			ApprovalURL: s.pageAddress(links.Approval, id),
		},
	}
	short := ""
	if issue {
		var err error
		if short, err = s.largeShortLink(ctx, links.Approval, id, expires, req.Cost); err != nil {
			return heldNotice{}, err
		}
	}
	switch {
	case short != "":
		n.pick, n.shortURL, n.ApprovalURL = handOver{URL: short, Kind: linkShort}, short, short
		n.PersonMessage, n.Links = approvalMessage(lead, n.pick, expiryLine(expires))
	case !issue && s.carriesLarge(req.Cost):
		// The short link handed over still works: the message points back.
		n.PersonMessage, n.Links = waitMessage(lead, expires)
	default:
		steps, err := approvalTooLargeSteps(runID)
		if err != nil {
			return heldNotice{}, err
		}
		n.reason, n.steps = reasonRequestTooLarge, steps
		n.PersonMessage = s.tooLargeMessage("The held write", req.Cost, expires, false)
		return n, nil
	}
	n.shortHeld = s.shortLinked(id)
	if noPasskey {
		n.reason = reasonNoPasskey
	}
	return n, nil
}

// DefaultApprovalWait is how long a write with approvalId waits for the
// person's signature when the call does not say (CONTRACT.md, Waiting
// write), under the 2 minutes after which Claude Code moves a tool call to
// the background.
const DefaultApprovalWait = 90 * time.Second

// credentialIDs are the registered passkeys that can sign on the pages the
// agent's links open (pagesPasskeys), for the request's allowCredentials:
// none is a request nobody can sign yet.
func (s *Service) credentialIDs(ctx context.Context) ([]passkey.Bytes, error) {
	all, err := s.Store.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	keys, _ := pagesPasskeys(all, s.PagesBase)
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids, nil
}

func approvalInvalid(reason, format string, args ...any) *toolresult.ToolError {
	return &toolresult.ToolError{Code: CodeApprovalInvalid, Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// differentWrite is the refusal of a write that is not the held one: its
// step repeats the held write exactly, with its approval id.
func differentWrite(a action.Approval, format string, args ...any) error {
	te := approvalInvalid(reasonDifferentWrite, format, args...)
	call := map[string]any{"sql": a.Statement, "intent": a.Intent, argRunID: a.RunID.String(), argApprovalID: a.ID.String()}
	var params []any
	if len(a.Params) > 0 && json.Unmarshal(a.Params, &params) == nil && len(params) > 0 {
		call["params"] = params
	}
	if steps, err := NewSteps().CallTool(toolWrite, call, "Send exactly the held write: this sql, these params and this intent, with its approvalId.").Build(); err == nil {
		te.NextSteps = steps
	}
	return te
}

// applyApproved runs a held write under its approval: the same statement,
// parameters and run as held, once the person signed on the page (waiting
// for it when asked). The guard checks it all again at commit.
func (s *Service) applyApproved(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.RunID == uuid.Nil {
		return WriteOutcome{}, &ArgumentError{Message: "approvalId needs the runId the write was held in"}
	}
	run, err := s.findRun(ctx, p.RunID)
	if err != nil {
		return WriteOutcome{}, err
	}
	a, err := s.Store.FindApproval(ctx, p.ApprovalID)
	if sentinel(err, theHost().ErrApprovalNotFound) {
		return WriteOutcome{}, approvalInvalid(reasonNotThisAgent, "approval %s is not one of this agent's held writes", p.ApprovalID)
	}
	if err != nil {
		return WriteOutcome{}, err
	}
	if err := sameAsHeld(a, p); err != nil {
		return WriteOutcome{}, err
	}
	if a, err = s.waitForSignature(ctx, a, p); err != nil {
		return WriteOutcome{}, err
	}
	// The receipt is built from Postgres's record of the approval after the
	// signature (CONTRACT.md, Receipts), and handed over only once the write
	// is applied.
	if a, err = s.Store.FindApproval(ctx, a.ID); err != nil {
		return WriteOutcome{}, err
	}
	var receipt *Receipt
	if a.Status == approvalApproved {
		r, err := s.approvalReceiptOf(a)
		if err != nil {
			return WriteOutcome{}, err
		}
		receipt = &r
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := s.Now()
	stmt, err := s.Store.Check(p.SQL, action.ToolWrite)
	op := stmt.Op
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, op, p.SQL, p.Params, start, err)
	}
	res, err := s.Store.WriteApproved(ctx, in, a.ID, op, p.SQL, p.Params)
	if err != nil {
		return WriteOutcome{}, s.withApprovalLink(ctx, a, s.refused(ctx, in, op, p.SQL, p.Params, start, err))
	}
	return WriteOutcome{
		WriteResult: res, RunID: run.ID, Op: op, ApprovalID: a.ID,
		Warnings: s.rlsWarnings(ctx, stmt.Tables, res.Rows), Receipt: receipt,
	}, nil
}

// withApprovalLink gives an approval error that sends the person back to the
// approval page (not signed yet, a bad signature, a passkey the database
// does not accept) the page's link in its steps; any other error passes.
func (s *Service) withApprovalLink(ctx context.Context, a action.Approval, err error) error {
	te := ToolError(err)
	if te.Code != CodeApprovalInvalid || len(te.NextSteps) > 0 {
		return err
	}
	switch te.Reason {
	case reasonNotSigned, reasonBadSignature, reasonPasskeyRevoked:
	default:
		return err
	}
	n, linkErr := s.approvalNotice(ctx, a.ID, a.RunID, requestOf(a), a.ExpiresAt, keepLink)
	if linkErr != nil {
		return linkErr
	}
	return s.approvalLinkError(te, n)
}

// sameAsHeld checks the call repeats the held write.
func sameAsHeld(a action.Approval, p WriteParams) error {
	switch {
	case a.Status == approvalApplied:
		return approvalInvalid(reasonAlreadyUsed, "approval %s was already used", a.ID)
	case a.Status == approvalExpired:
		return &toolresult.ToolError{Code: CodeApprovalExpired, Message: fmt.Sprintf("approval %s expired at %s; the write stays blocked", a.ID, timeText(a.ExpiresAt))}
	case a.RunID != p.RunID:
		return differentWrite(a, "approval %s belongs to run %s", a.ID, a.RunID)
	case a.Statement != p.SQL || !sameParams(a.Params, p.Params):
		return differentWrite(a, "sql and params must be exactly those of the held write")
	}
	return nil
}

// sameParams compares the held parameters (jsonb) with the call's. Numbers
// compare by their exact decimal value, never through float64:
// 9007199254740993 is not its rounded neighbor and 1e400 is not 1e399.
// jsonb keeps numbers exact but may respell them (1e2 is held as 100), so
// the text alone would refuse an exact repeat.
func sameParams(held json.RawMessage, params []any) bool {
	if len(held) == 0 && len(params) == 0 {
		return true
	}
	var a any
	if len(held) > 0 {
		var ok bool
		if a, ok = decodeExact(held); !ok {
			return false
		}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return false
	}
	b, ok := decodeExact(raw)
	return ok && sameJSON(a, b)
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

// awaitWhile polls while pending reports true: every s.Poll it calls
// refresh, until pending is false, the wait is over by s.Now, or ctx ends
// (then ctx's error). It holds no transaction between reads. The waiting
// write and request_revert's wait share it.
func (s *Service) awaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error {
	deadline := s.Now().Add(wait)
	tick := time.NewTicker(s.Poll)
	defer tick.Stop()
	for pending() && s.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		if err := refresh(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) awaitSigned(ctx context.Context, a action.Approval, wait time.Duration) (action.Approval, error) {
	err := s.awaitWhile(ctx, wait, func() bool { return a.Status == approvalPending }, func(ctx context.Context) error {
		// Each poll is one measured read with a budget of its own: polls
		// for 90 seconds must not add up against the call's budget.
		next, err := s.Store.FindApproval(budget.With(ctx), a.ID)
		if err != nil {
			return err
		}
		a = next
		return nil
	})
	return a, err
}

func (s *Service) waitForSignature(ctx context.Context, a action.Approval, p WriteParams) (action.Approval, error) {
	if a.Status != approvalPending || p.Wait == 0 {
		return a, nil
	}
	a, err := s.awaitSigned(ctx, a, p.Wait)
	if err != nil {
		return a, err
	}
	if a.Status == approvalPending {
		n, err := s.approvalNotice(ctx, a.ID, a.RunID, requestOf(a), a.ExpiresAt, keepLink)
		if err != nil {
			return a, err
		}
		return a, approvalStillPendingError(n)
	}
	return a, sameAsHeld(a, p) // it may have expired meanwhile
}
