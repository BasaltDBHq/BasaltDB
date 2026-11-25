package agent

import (
	"context"
	"errors"
	"time"

	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// maxReasonBytes is the limit of the guard's validating ledger functions
// (CONTRACT.md, basalt_meta) on a refusal's reason: up to 2000 bytes.
const maxReasonBytes = 2000

// WriteParams are one write call's validated arguments.
type WriteParams struct {
	Request agentstore.Request
	Intent  string
	RunID   uuid.UUID // uuid.Nil starts a one-write run with the intent
	// ApprovalID applies a held write the person approved on the page.
	ApprovalID uuid.UUID
	// Wait is how long to wait for the person to sign a held write before
	// answering APPROVAL_REQUIRED (CONTRACT.md, Waiting write); 0 answers
	// at once.
	Wait time.Duration
}

// WriteOutcome is one applied write.
type WriteOutcome struct {
	action.WriteResult
	RunID uuid.UUID
	Op    action.Op
	// ApprovalID is set when the write applied under an approval.
	ApprovalID uuid.UUID
	Warnings   []toolresult.Warning
	// Receipt is the approval's receipt when the write applied under one.
	Receipt *linksvc.Receipt
}

// Write checks the request against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
func (wc *Service) Write(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.ApprovalID != uuid.Nil {
		return wc.applyApproved(ctx, p)
	}
	run, err := wc.writeRun(ctx, p)
	if err != nil {
		return WriteOutcome{}, err
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := wc.core.Now()
	stmt, err := wc.store.Language.Check(p.Request, action.ToolWrite)
	op := stmt.Op
	if err != nil {
		return WriteOutcome{}, wc.refused(ctx, in, op, p.Request, start, err)
	}
	res, err := wc.store.Data.Write(ctx, in, p.Request, stmt)
	if errors.Is(err, action.ErrApprovalRequired) {
		id, expires, err := wc.hold(ctx, in, p, stmt, start)
		if id == uuid.Nil {
			return WriteOutcome{}, err
		}
		// The notice is made now, when the write is held, once: a call that
		// waits would otherwise keep the person from hearing of it until it
		// answers. Its link is the hold's own answer's, which is the answer
		// the agent gets unless the person signs first.
		wc.delivery.DeliverHeld(id, expires, err)
		if p.Wait == 0 {
			return WriteOutcome{}, err
		}
		// Held: wait for the person's signature and apply it, exactly as
		// the repeat with approvalId would. On timeout the answer is the
		// hold's own, which carries the link just issued.
		p.ApprovalID, p.RunID = id, run.ID
		out, waitErr := wc.applyApproved(ctx, p)
		var te *toolresult.ToolError
		if errors.As(waitErr, &te) && te.Code == guidance.CodeApprovalRequired {
			return WriteOutcome{}, err
		}
		return out, waitErr
	}
	if err != nil {
		return WriteOutcome{}, wc.refused(ctx, in, op, p.Request, start, err)
	}
	return WriteOutcome{WriteResult: res, RunID: run.ID, Op: op, Warnings: wc.rlsWarnings(ctx, stmt.Tables, res.Rows)}, nil
}

// writeRun finds the named run, or starts a one-write run.
func (wc *Service) writeRun(ctx context.Context, p WriteParams) (action.Run, error) {
	if p.RunID != uuid.Nil {
		return ledgersvc.FindRun(ctx, wc.store.Ledger, p.RunID)
	}
	info, err := wc.startRun(ctx, p.Intent, uuid.Nil)
	if err != nil {
		return action.Run{}, err
	}
	return action.Run{ID: info.RunID, TaskID: info.TaskID, Intent: info.Intent}, nil
}

// actionTool is the tool an action came from: query runs only a read
// (the store's check refuses anything else as WRONG_TOOL), write everything else.
// Failure maps the error by tool, so a refusal is recorded with the code
// the agent gets.
func actionTool(op action.Op) string {
	if op == action.OpRead {
		return guidance.ToolQuery
	}
	return guidance.ToolWrite
}

// refusalOp is the op the guard's record_refusal accepts.
func refusalOp(op action.Op) action.Op {
	switch op {
	case action.OpRead, action.OpInsert, action.OpUpdate, action.OpDelete:
		return op
	case action.OpMerge, action.OpOther:
		return action.OpOther
	}
	return action.OpOther
}
