package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"

	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
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
func (wc *Service) hold(ctx context.Context, in action.Intent, p WriteParams, stmt action.Statement, start time.Time) (uuid.UUID, time.Time, error) {
	assigned, err := wc.approvals.HoldColumns(ctx, p.Request)
	var notRepeatable *action.RefusalError
	if errors.As(err, &notRepeatable) {
		return uuid.Nil, time.Time{}, wc.refused(ctx, in, stmt.Op, p.Request, start, err)
	}
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	lines, err := wc.approvals.Preview(ctx, in, p.Request, assigned)
	if err != nil {
		return uuid.Nil, time.Time{}, wc.refused(ctx, in, stmt.Op, p.Request, start, err)
	}
	if len(lines) == 0 {
		// The rows went away between the attempt and the preview.
		return uuid.Nil, time.Time{}, &toolresult.ToolError{Code: guidance.CodeStoreError, Reason: guidance.ReasonNoRowsNow, Message: "the write changes no rows now; read again and decide"}
	}
	if te := approvalsvc.HoldTooLarge(lines, nil); te != nil {
		return uuid.Nil, time.Time{}, wc.refused(ctx, in, stmt.Op, p.Request, start, te)
	}
	held, err := wc.approvals.Hold(ctx, in, action.HoldRequest{Verb: string(stmt.Op), Statement: p.Request.Text, Params: p.Request.Params, Assigned: assigned, Lines: lines})
	if err != nil {
		if te := approvalsvc.HoldTooLarge(lines, err); te != nil {
			return uuid.Nil, time.Time{}, wc.refused(ctx, in, stmt.Op, p.Request, start, te)
		}
		return uuid.Nil, time.Time{}, err
	}
	req := linksvc.SizedRequest{Binding: held.BindingText, Lines: lines, Cost: linksvc.TextsCost(lines)}
	notice, err := wc.approvals.ApprovalNotice(ctx, held.ApprovalID, in.RunID, req, held.ExpiresAt, linksvc.IssueLink)
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	// The notice carries the long link, which works anywhere, and the
	// short one, which works only on this machine (CONTRACT.md, Link
	// secrets).
	sent := linksvc.HeldNotice{
		ApprovalID: held.ApprovalID, Agent: wc.core.Name, Intent: p.Intent, Statement: p.Request.Text,
		Rows: len(lines), Headline: notice.Headline, ExpiresAt: held.ExpiresAt, ApprovalURL: notice.LongURL,
		ShortURL: notice.ShortURL,
	}
	if err := wc.delivery.NotifyHeldTo(context.WithoutCancel(ctx), sent); err != nil {
		wc.core.Log.Error("notify held write", "approvalId", held.ApprovalID, "err", err)
	}
	return held.ApprovalID, held.ExpiresAt, approvalsvc.ApprovalRequiredError(notice)
}

// applyApproved runs a held write under its approval: the same statement,
// parameters and run as held, once the person signed on the page (waiting
// for it when asked). The guard checks it all again at commit.
func (wc *Service) applyApproved(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.RunID == uuid.Nil {
		return WriteOutcome{}, &guidance.ArgumentError{Message: "approvalId needs the runId the write was held in"}
	}
	run, err := ledgersvc.FindRun(ctx, wc.store.Ledger, p.RunID)
	if err != nil {
		return WriteOutcome{}, err
	}
	a, err := wc.approvals.FindApproval(ctx, p.ApprovalID)
	if action.IsApprovalRefused(err, action.ApprovalNotFound) {
		return WriteOutcome{}, approvalsvc.ApprovalInvalid(guidance.ReasonNotThisAgent, "approval %s is not one of this agent's held writes", p.ApprovalID)
	}
	if err != nil {
		return WriteOutcome{}, err
	}
	if err := wc.sameAsHeld(a, p); err != nil {
		return WriteOutcome{}, err
	}
	if a, err = wc.waitForSignature(ctx, a, p); err != nil {
		return WriteOutcome{}, err
	}
	// The receipt is built from Postgres's record of the approval after the
	// signature (CONTRACT.md, Receipts), and handed over only once the write
	// is applied.
	if a, err = wc.approvals.FindApproval(ctx, a.ID); err != nil {
		return WriteOutcome{}, err
	}
	var receipt *linksvc.Receipt
	if a.Status == action.ApprovalApproved {
		r, err := wc.delivery.ApprovalReceiptOf(a)
		if err != nil {
			return WriteOutcome{}, err
		}
		receipt = &r
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := wc.core.Now()
	stmt, err := wc.store.Language.Check(p.Request, action.ToolWrite)
	op := stmt.Op
	if err != nil {
		return WriteOutcome{}, wc.refused(ctx, in, op, p.Request, start, err)
	}
	res, err := wc.store.Data.WriteApproved(ctx, in, a.ID, p.Request, stmt)
	if err != nil {
		return WriteOutcome{}, wc.withApprovalLink(ctx, a, wc.refused(ctx, in, op, p.Request, start, err))
	}
	return WriteOutcome{
		WriteResult: res, RunID: run.ID, Op: op, ApprovalID: a.ID,
		Warnings: wc.rlsWarnings(ctx, stmt.Tables, res.Rows), Receipt: receipt,
	}, nil
}

// withApprovalLink gives an approval error that sends the person back to the
// approval page (not signed yet, a bad signature, a passkey the database
// does not accept) the page's link in its steps; any other error passes.
func (wc *Service) withApprovalLink(ctx context.Context, a action.Approval, err error) error {
	te := wc.core.Errors.ToolError(err)
	if te.Code != guidance.CodeApprovalInvalid || len(te.NextSteps) > 0 {
		return err
	}
	switch te.Reason {
	case guidance.ReasonNotSigned, guidance.ReasonBadSignature, guidance.ReasonPasskeyRevoked:
	default:
		return err
	}
	n, linkErr := wc.approvals.ApprovalNotice(ctx, a.ID, a.RunID, approvalsvc.RequestOf(a), a.ExpiresAt, linksvc.KeepLink)
	if linkErr != nil {
		return linkErr
	}
	return wc.next.ApprovalLinkError(te, n)
}

// sameAsHeld checks the call repeats the held write.
func (wc *Service) sameAsHeld(a action.Approval, p WriteParams) error {
	switch {
	case a.Status == action.ApprovalApplied:
		return approvalsvc.ApprovalInvalid(guidance.ReasonAlreadyUsed, "approval %s was already used", a.ID)
	case a.Status == action.ApprovalExpired:
		return &toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: fmt.Sprintf("approval %s expired at %s; the write stays blocked", a.ID, guidance.TimeText(a.ExpiresAt))}
	case a.RunID != p.RunID:
		return approvalsvc.DifferentWrite(a, wc.heldArgs(a), "approval %s belongs to run %s", a.ID, a.RunID)
	case a.Request.Text != p.Request.Text || !sameParams(a.Request.Params, p.Request.Params):
		return approvalsvc.DifferentWrite(a, wc.heldArgs(a), "the request must be exactly the held write's")
	}
	return nil
}

// heldArgs is the held request as the store family's write tool takes it.
// Params that do not decode are left out, as are none.
func (wc *Service) heldArgs(a action.Approval) map[string]any {
	req := agentstore.Request{Text: a.Request.Text}
	if len(a.Request.Params) > 0 {
		var params []any
		if json.Unmarshal(a.Request.Params, &params) == nil {
			req.Params = params
		}
	}
	return wc.store.Language.Args(req)
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

func (wc *Service) awaitSigned(ctx context.Context, a action.Approval, wait time.Duration) (action.Approval, error) {
	err := wc.delivery.AwaitWhile(ctx, wait, func() bool { return a.Status == action.ApprovalPending }, func(ctx context.Context) error {
		// Each poll is one measured read with a budget of its own: polls
		// for 90 seconds must not add up against the call's budget.
		next, err := wc.approvals.FindApproval(budget.With(ctx), a.ID)
		if err != nil {
			return err
		}
		a = next
		return nil
	})
	return a, err
}

func (wc *Service) waitForSignature(ctx context.Context, a action.Approval, p WriteParams) (action.Approval, error) {
	if a.Status != action.ApprovalPending || p.Wait == 0 {
		return a, nil
	}
	a, err := wc.awaitSigned(ctx, a, p.Wait)
	if err != nil {
		return a, err
	}
	if a.Status == action.ApprovalPending {
		n, err := wc.approvals.ApprovalNotice(ctx, a.ID, a.RunID, approvalsvc.RequestOf(a), a.ExpiresAt, linksvc.KeepLink)
		if err != nil {
			return a, err
		}
		return a, approvalsvc.ApprovalStillPendingError(n)
	}
	return a, wc.sameAsHeld(a, p) // it may have expired meanwhile
}
