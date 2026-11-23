package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// hold turns a write the guard held into a held action (decision M2-1):
// refuse it when it is not repeatable, preview it in a transaction that
// rolls back, store it with its lines, notify the person, and answer
// APPROVAL_REQUIRED with the approval link. It returns the held write's
// approval id and expiry with the APPROVAL_REQUIRED error, or uuid.Nil and
// the error that kept it from being held.
func (s *Service) hold(ctx context.Context, in action.Intent, p WriteParams, stmt action.Statement, start time.Time) (uuid.UUID, time.Time, error) {
	assigned, err := s.deps.Approval.Store.HoldColumns(ctx, p.SQL, p.Params)
	var notRepeatable *action.RefusalError
	if errors.As(err, &notRepeatable) {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	lines, err := s.deps.Approval.Store.Preview(ctx, in, p.SQL, p.Params, assigned)
	if err != nil {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	if len(lines) == 0 {
		// The rows went away between the attempt and the preview.
		return uuid.Nil, time.Time{}, &toolresult.ToolError{Code: guidance.CodeSQLError, Reason: guidance.ReasonNoRowsNow, Message: "the write changes no rows now; read again and decide"}
	}
	if te := holdTooLarge(lines, nil); te != nil {
		return uuid.Nil, time.Time{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, te)
	}
	held, err := s.deps.Approval.Store.Hold(ctx, in, action.HoldRequest{Statement: p.SQL, Params: p.Params, Assigned: assigned, Lines: lines})
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
		ApprovalID: held.ApprovalID, Agent: s.deps.Core.Name, Intent: p.Intent, Statement: p.SQL,
		Rows: len(lines), Headline: notice.Headline, ExpiresAt: held.ExpiresAt, ApprovalURL: notice.longURL,
		ShortURL: notice.shortURL,
	}
	if err := s.deps.Delivery.Notifier.NotifyHeld(context.WithoutCancel(ctx), sent); err != nil {
		s.deps.Core.Log.Error("notify held write", "approvalId", held.ApprovalID, "err", err)
	}
	return held.ApprovalID, held.ExpiresAt, approvalRequiredError(notice)
}

// applyApproved runs a held write under its approval: the same statement,
// parameters and run as held, once the person signed on the page (waiting
// for it when asked). The guard checks it all again at commit.
func (s *Service) applyApproved(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.RunID == uuid.Nil {
		return WriteOutcome{}, &guidance.ArgumentError{Message: "approvalId needs the runId the write was held in"}
	}
	run, err := findRun(ctx, s.deps.Core.Store, p.RunID)
	if err != nil {
		return WriteOutcome{}, err
	}
	a, err := s.deps.Approval.Store.FindApproval(ctx, p.ApprovalID)
	if guidance.Sentinel(err, s.deps.Approval.ErrNotFound) {
		return WriteOutcome{}, approvalInvalid(guidance.ReasonNotThisAgent, "approval %s is not one of this agent's held writes", p.ApprovalID)
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
	if a, err = s.deps.Approval.Store.FindApproval(ctx, a.ID); err != nil {
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
	start := s.deps.Core.Now()
	stmt, err := s.deps.Write.Store.Check(p.SQL, action.ToolWrite)
	op := stmt.Op
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, op, p.SQL, p.Params, start, err)
	}
	res, err := s.deps.Write.Store.WriteApproved(ctx, in, a.ID, op, p.SQL, p.Params)
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
	te := s.deps.Core.Errors.ToolError(err)
	if te.Code != guidance.CodeApprovalInvalid || len(te.NextSteps) > 0 {
		return err
	}
	switch te.Reason {
	case guidance.ReasonNotSigned, guidance.ReasonBadSignature, guidance.ReasonPasskeyRevoked:
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
		return approvalInvalid(guidance.ReasonAlreadyUsed, "approval %s was already used", a.ID)
	case a.Status == approvalExpired:
		return &toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: fmt.Sprintf("approval %s expired at %s; the write stays blocked", a.ID, guidance.TimeText(a.ExpiresAt))}
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

func (s *Service) awaitSigned(ctx context.Context, a action.Approval, wait time.Duration) (action.Approval, error) {
	err := s.awaitWhile(ctx, wait, func() bool { return a.Status == approvalPending }, func(ctx context.Context) error {
		// Each poll is one measured read with a budget of its own: polls
		// for 90 seconds must not add up against the call's budget.
		next, err := s.deps.Approval.Store.FindApproval(budget.With(ctx), a.ID)
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
