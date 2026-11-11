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
// APPROVAL_REQUIRED with the approval link.
func (s *Service) hold(ctx context.Context, in guard.Intent, p WriteParams, stmt sqlguard.Statement, start time.Time) error {
	h, err := sqlguard.CheckRepeatable(p.SQL)
	if err != nil {
		return s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	assigned := h.Assigned
	if assigned == nil {
		if assigned, err = s.Approvals.TableColumns(ctx, h.Table); err != nil {
			return err
		}
	}
	lines, err := s.Approvals.Preview(ctx, in, p.SQL, p.Params, assigned)
	if err != nil {
		return s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if len(lines) == 0 {
		// The rows went away between the attempt and the preview.
		return &mcp.ToolError{Code: CodeSQLError, Message: "the write changes no rows now; read again and decide"}
	}
	held, err := s.Approvals.Hold(ctx, in, guard.HoldRequest{Statement: p.SQL, Params: p.Params, Assigned: assigned, Lines: lines})
	if err != nil {
		return err
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return err
	}
	link, err := s.approvalURL(ids, held.ApprovalID, held.BindingText, lines)
	if err != nil {
		return err
	}
	summary, err := approval.SummarizeText(lines)
	if err != nil {
		return err
	}
	notice := HeldNotice{
		ApprovalID: held.ApprovalID, Agent: s.Name, Intent: p.Intent, Statement: p.SQL,
		Rows: len(lines), Headline: summary.Headline(), ExpiresAt: held.ExpiresAt, ApprovalURL: link,
	}
	if err := s.Notifier.NotifyHeld(context.WithoutCancel(ctx), notice); err != nil {
		s.Log.Error("notify held write", "approvalId", held.ApprovalID, "err", err)
	}
	return &mcp.ToolError{
		Code: CodeApprovalRequired,
		Message: fmt.Sprintf("held for the person's approval: %d rows. Give the person the approvalUrl; once they approve with their passkey, "+
			"call write again with the same arguments plus approvalId (and approval, if they give you the code). It expires at %s.",
			len(lines), timeText(held.ExpiresAt)),
		Approval: &mcp.ApprovalNotice{
			ApprovalID: held.ApprovalID.String(), ExpiresAt: timeText(held.ExpiresAt), Rows: len(lines), ApprovalURL: link,
		},
	}
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

// approvalURL builds the approval link for a held write.
func (s *Service) approvalURL(ids []passkey.Bytes, id uuid.UUID, binding string, lines []string) (string, error) {
	return approval.Request{ApprovalID: id, Binding: binding, Lines: lines, CredentialIDs: ids}.URL(s.ApprovalPage)
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

// PendingItem is one open held write with its approval link.
type PendingItem struct {
	ledger.Approval
	ApprovalURL string
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
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return pagination.Page[PendingItem]{}, err
	}
	out := pagination.Page[PendingItem]{Items: make([]PendingItem, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, a := range page.Items {
		link, err := s.approvalURL(ids, a.ID, a.BindingText, a.Lines)
		if err != nil {
			return pagination.Page[PendingItem]{}, err
		}
		out.Items = append(out.Items, PendingItem{Approval: a, ApprovalURL: link})
	}
	return out, nil
}
