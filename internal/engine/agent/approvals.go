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
	notice, err := s.approvalNotice(ctx, held.ApprovalID, held.BindingText, lines, held.ExpiresAt)
	if err != nil {
		return uuid.Nil, err
	}
	// Telegram gets the long link: the short one works only on this
	// machine (CONTRACT.md, Approvals, Engine).
	sent := HeldNotice{
		ApprovalID: held.ApprovalID, Agent: s.Name, Intent: p.Intent, Statement: p.SQL,
		Rows: len(lines), Headline: notice.Headline, ExpiresAt: held.ExpiresAt, ApprovalURL: notice.longURL,
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
	longURL string
}

// approvalNotice builds what the agent shows the person about a held
// write: its headline, the link (short when this engine serves the pages),
// the equivalent command and one line to show verbatim.
func (s *Service) approvalNotice(ctx context.Context, id uuid.UUID, binding string, lines []string, expires time.Time) (heldNotice, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return heldNotice{}, err
	}
	long, err := approval.Request{ApprovalID: id, Binding: binding, Lines: lines, CredentialIDs: ids}.URL(s.ApprovalPage)
	if err != nil {
		return heldNotice{}, err
	}
	summary, err := approval.SummarizeText(lines)
	if err != nil {
		return heldNotice{}, err
	}
	command := s.approveCommand(id)
	link := s.shortLink(approvePath, id, long)
	how := fmt.Sprintf("Approve: %s (or run: %s)", link, command)
	if link == long {
		// The long link carries the whole preview and breaks when copied:
		// the message names the command, approvalUrl still has the link.
		how = fmt.Sprintf("Approve by running: %s (it opens the approval page)", command)
	}
	return heldNotice{
		ApprovalNotice: mcp.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: timeText(expires), Rows: len(lines), Headline: summary.Headline(),
			ApprovalURL: link, ApproveCommand: command,
			PersonMessage: fmt.Sprintf("Held for your approval: %s. %s. Expires %s.", summary.Headline(), how, expires.UTC().Format(personTime)),
		},
		longURL: long,
	}, nil
}

// personTime is how a person-facing message states a deadline.
const personTime = "2006-01-02 15:04 UTC"

// Paths of the engine's local pages (CONTRACT.md, Local pages).
const (
	approvePath = "/approve/"
	revertPath  = "/revert/"
)

// shortLink is the page link <origin><path><id> when this engine serves
// the pages, else long.
func (s *Service) shortLink(path string, id uuid.UUID, long string) string {
	if s.PagesOrigin == "" {
		return long
	}
	return s.PagesOrigin + path + id.String()
}

// approvalRequiredError is the APPROVAL_REQUIRED answer for a held write.
func approvalRequiredError(n heldNotice) error {
	notice := n.ApprovalNotice
	return &mcp.ToolError{
		Code: CodeApprovalRequired,
		Message: fmt.Sprintf("held for the person's approval: %d rows. Show the person approval.personMessage verbatim, "+
			"then call write again with the same arguments plus approvalId: it waits up to %d seconds for their passkey "+
			"and returns APPLIED as soon as they approve (if it times out, repeat it). If they give you an approval code, "+
			"pass it as approval. It expires at %s.",
			notice.Rows, int(DefaultApprovalWait.Seconds()), notice.ExpiresAt),
		Approval: &notice,
	}
}

// DefaultApprovalWait is how long a write with approvalId waits for the
// person's signature when the call does not say (CONTRACT.md, Waiting
// write), under the 2 minutes after which Claude Code moves a tool call to
// the background.
const DefaultApprovalWait = 90 * time.Second

// approveCommand is the command that opens a held write's approval page in
// the person's browser: short enough to copy from a chat.
func (s *Service) approveCommand(id uuid.UUID) string {
	return "basalt approve " + s.CLIFlags + " --open " + id.String()
}

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

// ListPending returns one page of the agent's open held writes.
func (s *Service) ListPending(ctx context.Context, p ledger.ApprovalListParams) (pagination.Page[PendingItem], error) {
	if _, err := s.findRun(ctx, p.RunID); err != nil {
		return pagination.Page[PendingItem]{}, err
	}
	page, err := s.Approvals.ListApprovals(ctx, p)
	if err != nil {
		return pagination.Page[PendingItem]{}, err
	}
	out := pagination.Page[PendingItem]{Items: make([]PendingItem, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, a := range page.Items {
		n, err := s.approvalNotice(ctx, a.ID, a.BindingText, a.Lines, a.ExpiresAt)
		if err != nil {
			return pagination.Page[PendingItem]{}, err
		}
		out.Items = append(out.Items, PendingItem{Approval: a, Notice: n.ApprovalNotice})
	}
	return out, nil
}

// approvalPoll is how often a waiting write checks for the signature.
const approvalPoll = time.Second

// awaitSigned waits up to wait for the person to sign a, checking about
// once a second, and returns a as last read: still PENDING on timeout.
// The signature may come from the page's relay, basalt approve or another
// call; Postgres is the only place that knows.
func (s *Service) awaitSigned(ctx context.Context, a ledger.Approval, wait time.Duration) (ledger.Approval, error) {
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	tick := time.NewTicker(approvalPoll)
	defer tick.Stop()
	for a.Status == ledger.ApprovalPending {
		select {
		case <-ctx.Done():
			return a, ctx.Err()
		case <-timeout.C:
			return a, nil
		case <-tick.C:
		}
		next, err := s.Approvals.FindApproval(ctx, a.ID)
		if err != nil {
			return a, err
		}
		a = next
	}
	return a, nil
}

// waitForSignature waits for an unsigned held write when the call asks to
// (p.Wait) and gave no code. It answers APPROVAL_REQUIRED again when the
// person did not sign in time, and the approval as it is now otherwise.
func (s *Service) waitForSignature(ctx context.Context, a ledger.Approval, p WriteParams) (ledger.Approval, error) {
	if a.Status != ledger.ApprovalPending || p.Approval != "" || p.Wait == 0 {
		return a, nil
	}
	a, err := s.awaitSigned(ctx, a, p.Wait)
	if err != nil {
		return a, err
	}
	if a.Status == ledger.ApprovalPending {
		n, err := s.approvalNotice(ctx, a.ID, a.BindingText, a.Lines, a.ExpiresAt)
		if err != nil {
			return a, err
		}
		return a, approvalRequiredError(n)
	}
	return a, sameAsHeld(a, p) // it may have expired meanwhile
}
