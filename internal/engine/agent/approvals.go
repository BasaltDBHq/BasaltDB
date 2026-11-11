package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// ApprovalStore holds writes for approval and applies approved ones, on the
// agent's own credential.
type ApprovalStore interface {
	Preview(ctx context.Context, in guard.Intent, sql string, params []any, assigned []string) ([]string, error)
	Hold(ctx context.Context, in guard.Intent, r guard.HoldRequest) (guard.Held, error)
	TableColumns(ctx context.Context, table string) ([]string, error)
	WriteApproved(ctx context.Context, in guard.Intent, approvalID uuid.UUID, op sqlguard.Op, sql string, params []any) (agentdb.WriteResult, error)
	SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error)
	FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error)
	ListApprovals(ctx context.Context, p ledger.ApprovalListParams) (pagination.Page[ledger.Approval], error)
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
}

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

// Notifier tells the person a write is held (Telegram, when configured).
// It only delivers the link; the approval needs the person's passkey.
type Notifier interface {
	NotifyHeld(ctx context.Context, n HeldNotice) error
}

// noNotifier is the Notifier when none is configured.
type noNotifier struct{}

func (noNotifier) NotifyHeld(context.Context, HeldNotice) error { return nil }

// sqlstateApprovalRequired is the guard's BS002.
const sqlstateApprovalRequired = "BS002"

func approvalRequired(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == sqlstateApprovalRequired
}

// hold turns a write the guard held into a held action (decision M2-1):
// refuse it when it is not repeatable, preview it in a transaction that
// rolls back, store it with its lines, notify the person, and answer
// APPROVAL_REQUIRED with the approval link. It returns the held write's
// approval id with the APPROVAL_REQUIRED error, or uuid.Nil and the error
// that kept it from being held.
func (s *Service) hold(ctx context.Context, in guard.Intent, p WriteParams, stmt sqlguard.Statement, start time.Time) (uuid.UUID, error) {
	h, err := sqlguard.CheckRepeatable(p.SQL)
	if err != nil {
		return uuid.Nil, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	assigned := h.Assigned
	if assigned == nil {
		if assigned, err = s.Approvals.TableColumns(ctx, h.Table); err != nil {
			return uuid.Nil, err
		}
	}
	lines, err := s.Approvals.Preview(ctx, in, p.SQL, p.Params, assigned)
	if err != nil {
		return uuid.Nil, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if len(lines) == 0 {
		// The rows went away between the attempt and the preview.
		return uuid.Nil, &mcp.ToolError{Code: CodeSQLError, Message: "the write changes no rows now; read again and decide"}
	}
	held, err := s.Approvals.Hold(ctx, in, guard.HoldRequest{Statement: p.SQL, Params: p.Params, Assigned: assigned, Lines: lines})
	if err != nil {
		return uuid.Nil, err
	}
	notice, err := s.approvalNotice(ctx, held.ApprovalID, held.BindingText, lines, held.ExpiresAt, issueLink)
	if err != nil {
		return uuid.Nil, err
	}
	// Telegram's button gets the long link: the short one works only on
	// this machine; its text carries the short one too (CONTRACT.md, Link
	// secrets).
	sent := HeldNotice{
		ApprovalID: held.ApprovalID, Agent: s.Name, Intent: p.Intent, Statement: p.SQL,
		Rows: len(lines), Headline: notice.Headline, ExpiresAt: held.ExpiresAt, ApprovalURL: notice.longURL,
		ShortURL: notice.shortURL,
	}
	if err := s.Notifier.NotifyHeld(context.WithoutCancel(ctx), sent); err != nil {
		s.Log.Error("notify held write", "approvalId", held.ApprovalID, "err", err)
	}
	return held.ApprovalID, approvalRequiredError(notice)
}

// heldNotice is a held write as the agent hands it to the person
// (CONTRACT.md, Handing a held action to the person), with the long link
// for notifications.
type heldNotice struct {
	mcp.ApprovalNotice
	longURL  string
	shortURL string // "" when no short link was issued
}

// Whether building a notice issues a new short link, revoking the item's
// earlier one (CONTRACT.md, Link secrets).
const (
	issueLink = true
	keepLink  = false
)

// approvalNotice builds what the agent shows the person about a held
// write: its headline, the link (a newly issued short link when this
// engine serves the pages and issue is set, else the long one), the
// equivalent command and one line to show verbatim.
func (s *Service) approvalNotice(ctx context.Context, id uuid.UUID, binding string, lines []string, expires time.Time, issue bool) (heldNotice, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return heldNotice{}, err
	}
	long, err := approval.Request{ApprovalID: id, Binding: binding, Lines: lines, CredentialIDs: ids}.URL(s.PagesBase)
	if err != nil {
		return heldNotice{}, err
	}
	summary, err := approval.SummarizeText(lines)
	if err != nil {
		return heldNotice{}, err
	}
	command := s.Commands.Approve(id)
	short, err := s.shortLink(links.Approval, id, expires, issue)
	if err != nil {
		return heldNotice{}, err
	}
	link, how := short, fmt.Sprintf("Approve: %s (or run: %s)", short, command)
	switch {
	case short == "" && (issue || s.PagesOrigin == ""):
		// No local pages. The long link carries the whole preview and
		// breaks when copied: the message names the command, approvalUrl
		// still has the link.
		link, how = long, fmt.Sprintf("Approve by running: %s (it opens the approval page)", command)
	case short == "":
		// A wait that timed out: the link already handed over still works.
		link, how = long, fmt.Sprintf("Approve with the link you were given, or run: %s", command)
	}
	return heldNotice{
		ApprovalNotice: mcp.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: timeText(expires), Rows: len(lines), Headline: summary.Headline(),
			ApprovalURL: link, ApproveCommand: command,
			PersonMessage: fmt.Sprintf("Held for your approval: %s. %s. Expires %s.", summary.Headline(), how, expires.UTC().Format(personTime)),
		},
		longURL:  long,
		shortURL: short,
	}, nil
}

// personTime is how a person-facing message states a deadline.
const personTime = "2006-01-02 15:04 UTC"

// shortLink issues a new short link page(origin, id)#s=<secret> for an
// item that expires at expires, revoking its earlier one, when this engine
// serves the pages and issue is set; else "".
func (s *Service) shortLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error) {
	if s.PagesOrigin == "" || !issue {
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
		"for their passkey and returns APPLIED as soon as they approve. %s If they give you an approval code, pass it as approval. "+
		"It expires at %s.",
		n.Rows, int(DefaultApprovalWait.Seconds()), afterWaitRunsOut, n.ExpiresAt))
}

// approvalStillPendingError is the APPROVAL_REQUIRED answer of a wait
// that ran out: no second wait, the person may take long.
func approvalStillPendingError(n heldNotice) error {
	return approvalError(n, fmt.Sprintf("still waiting for the person's approval of %d rows; nothing was applied. "+
		"Do not call write to wait again. End your turn: tell the person the write is waiting for their approval "+
		"(approval.personMessage has the link and the command), that it expires at %s, and that you apply it when they "+
		"tell you they approved. Then call write with the same arguments plus approvalId: it applies at once.",
		n.Rows, n.ExpiresAt))
}

// afterWaitRunsOut tells the agent what to do when its one wait for a
// person's approval returns APPROVAL_REQUIRED again.
const afterWaitRunsOut = "If that call returns APPROVAL_REQUIRED again, its wait ran out: do not wait again, " +
	"end your turn as its message says."

func approvalError(n heldNotice, message string) error {
	notice := n.ApprovalNotice
	return &mcp.ToolError{Code: CodeApprovalRequired, Message: message, Approval: &notice}
}

// DefaultApprovalWait is how long a write with approvalId waits for the
// person's signature when the call does not say (CONTRACT.md, Waiting
// write), under the 2 minutes after which Claude Code moves a tool call to
// the background.
const DefaultApprovalWait = 90 * time.Second

// credentialIDs are the registered passkeys, for the request's
// allowCredentials.
func (s *Service) credentialIDs(ctx context.Context) ([]passkey.Bytes, error) {
	keys, err := s.Approvals.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids, nil
}

func approvalInvalid(format string, args ...any) error {
	return &mcp.ToolError{Code: CodeApprovalInvalid, Message: fmt.Sprintf(format, args...)}
}

// applyApproved runs a held write under its approval: the same statement,
// parameters and run as held, after relaying the person's signed approval
// when the agent was given it. The guard checks it all again at commit.
func (s *Service) applyApproved(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.RunID == uuid.Nil {
		return WriteOutcome{}, &ArgumentError{Message: "approvalId needs the runId the write was held in"}
	}
	run, err := s.findRun(ctx, p.RunID)
	if err != nil {
		return WriteOutcome{}, err
	}
	a, err := s.Approvals.FindApproval(ctx, p.ApprovalID)
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return WriteOutcome{}, approvalInvalid("approval %s is not one of this agent's held writes", p.ApprovalID)
	}
	if err != nil {
		return WriteOutcome{}, err
	}
	if err := sameAsHeld(a, p); err != nil {
		return WriteOutcome{}, err
	}
	if err := s.relay(ctx, a, p.Approval); err != nil {
		return WriteOutcome{}, err
	}
	if a, err = s.waitForSignature(ctx, a, p); err != nil {
		return WriteOutcome{}, err
	}
	in := guard.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := s.Now()
	stmt, err := sqlguard.Check(p.SQL, sqlguard.ToolWrite)
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	res, err := s.Approvals.WriteApproved(ctx, in, a.ID, stmt.Op, p.SQL, p.Params)
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	return WriteOutcome{WriteResult: res, RunID: run.ID, Op: stmt.Op, ApprovalID: a.ID}, nil
}

// sameAsHeld checks the call repeats the held write.
func sameAsHeld(a ledger.Approval, p WriteParams) error {
	switch {
	case a.Status == ledger.ApprovalApplied:
		return approvalInvalid("approval %s was already used", a.ID)
	case a.Status == ledger.ApprovalExpired:
		return &mcp.ToolError{Code: CodeApprovalExpired, Message: fmt.Sprintf("approval %s expired at %s; the write stays blocked", a.ID, timeText(a.ExpiresAt))}
	case a.RunID != p.RunID:
		return approvalInvalid("approval %s belongs to run %s", a.ID, a.RunID)
	case a.Statement != p.SQL || !sameParams(a.Params, p.Params):
		return approvalInvalid("sql and params must be exactly those of the held write")
	}
	return nil
}

// sameParams compares the held parameters (jsonb) with the call's.
func sameParams(held json.RawMessage, params []any) bool {
	var a, b any
	if len(held) > 0 && json.Unmarshal(held, &a) != nil {
		return false
	}
	raw, err := json.Marshal(params)
	if err != nil || json.Unmarshal(raw, &b) != nil {
		return false
	}
	if len(held) == 0 && len(params) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// relay submits the person's response code for a, when given and not yet
// signed. The code is untrusted; Postgres verifies the signature.
func (s *Service) relay(ctx context.Context, a ledger.Approval, code string) error {
	if code == "" || a.Status == ledger.ApprovalApproved {
		return nil
	}
	resp, err := approval.ParseResponse(code)
	if err != nil {
		return approvalInvalid("the approval code is damaged: %v", err)
	}
	if resp.ApprovalID != a.ID {
		return approvalInvalid("the approval code is for approval %s, not %s", resp.ApprovalID, a.ID)
	}
	_, err = s.Approvals.SubmitApproval(ctx, a.ID, resp.Assertion())
	return err
}

// PendingItem is one open held write with what the agent hands the person.
type PendingItem struct {
	ledger.Approval
	Notice mcp.ApprovalNotice
}

// ListPending returns one page of the agent's open held writes. It touches
// no link unless reissue is set: then each item gets a new short link and
// its earlier one stops working (CONTRACT.md, Link secrets).
func (s *Service) ListPending(ctx context.Context, p ledger.ApprovalListParams, reissue bool) (pagination.Page[PendingItem], error) {
	if _, err := s.findRun(ctx, p.RunID); err != nil {
		return pagination.Page[PendingItem]{}, err
	}
	page, err := s.Approvals.ListApprovals(ctx, p)
	if err != nil {
		return pagination.Page[PendingItem]{}, err
	}
	out := pagination.Page[PendingItem]{Items: make([]PendingItem, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, a := range page.Items {
		n, err := s.approvalNotice(ctx, a.ID, a.BindingText, a.Lines, a.ExpiresAt, reissue)
		if err != nil {
			return pagination.Page[PendingItem]{}, err
		}
		out.Items = append(out.Items, PendingItem{Approval: a, Notice: n.ApprovalNotice})
	}
	return out, nil
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

func (s *Service) awaitSigned(ctx context.Context, a ledger.Approval, wait time.Duration) (ledger.Approval, error) {
	err := s.awaitWhile(ctx, wait, func() bool { return a.Status == ledger.ApprovalPending }, func(ctx context.Context) error {
		next, err := s.Approvals.FindApproval(ctx, a.ID)
		if err != nil {
			return err
		}
		a = next
		return nil
	})
	return a, err
}

func (s *Service) waitForSignature(ctx context.Context, a ledger.Approval, p WriteParams) (ledger.Approval, error) {
	if a.Status != ledger.ApprovalPending || p.Approval != "" || p.Wait == 0 {
		return a, nil
	}
	a, err := s.awaitSigned(ctx, a, p.Wait)
	if err != nil {
		return a, err
	}
	if a.Status == ledger.ApprovalPending {
		n, err := s.approvalNotice(ctx, a.ID, a.BindingText, a.Lines, a.ExpiresAt, keepLink)
		if err != nil {
			return a, err
		}
		return a, approvalStillPendingError(n)
	}
	return a, sameAsHeld(a, p) // it may have expired meanwhile
}
