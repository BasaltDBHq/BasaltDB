package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Limits of the guard's validating ledger functions (CONTRACT.md,
// basalt_meta): statements and parameters up to 64 KiB, reasons up to
// 2000 bytes.
const (
	maxParamsBytes = 64 << 10
	maxReasonBytes = 2000
)

// WriteStore is the part of the agent's store the query and write tools
// run on.
type WriteStore interface {
	statementChecker
	// Read runs one read, with the versions of the rows of the statement's
	// sources it can identify.
	Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error)
	// Write runs one write through the guard.
	Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any) (action.WriteResult, error)
	// WriteApproved is Write under the person's signed approval.
	WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any) (action.WriteResult, error)
}

// WriteParams are one write call's validated arguments.
type WriteParams struct {
	SQL    string
	Params []any
	Intent string
	RunID  uuid.UUID // uuid.Nil starts a one-write run with the intent
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

// Write checks sql against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
func (wc *writeCase) Write(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.ApprovalID != uuid.Nil {
		return wc.applyApproved(ctx, p)
	}
	run, err := wc.writeRun(ctx, p)
	if err != nil {
		return WriteOutcome{}, err
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := wc.core.Now()
	stmt, err := wc.deps.Store.Check(p.SQL, action.ToolWrite)
	if err == nil {
		err = checkArgs(stmt, p.Params)
	}
	op := stmt.Op
	if err != nil {
		return WriteOutcome{}, wc.refused(ctx, in, op, p.SQL, p.Params, start, err)
	}
	res, err := wc.deps.Store.Write(ctx, in, op, p.SQL, p.Params)
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
		return WriteOutcome{}, wc.refused(ctx, in, op, p.SQL, p.Params, start, err)
	}
	return WriteOutcome{WriteResult: res, RunID: run.ID, Op: op, Warnings: wc.rlsWarnings(ctx, stmt.Tables, res.Rows)}, nil
}

// writeRun finds the named run, or starts a one-write run.
func (wc *writeCase) writeRun(ctx context.Context, p WriteParams) (action.Run, error) {
	if p.RunID != uuid.Nil {
		return ledgersvc.FindRun(ctx, wc.core.Store, p.RunID)
	}
	info, err := wc.startRun(ctx, p.Intent, uuid.Nil)
	if err != nil {
		return action.Run{}, err
	}
	return action.Run{ID: info.RunID, TaskID: info.TaskID, Intent: info.Intent}, nil
}

// actionTool is the tool an action came from: query runs only a SELECT
// (the store's check refuses anything else as WRONG_TOOL), write everything else.
// Failure maps the error by tool, so a refusal is recorded with the code
// the agent gets.
func actionTool(op action.Op) string {
	if op == action.OpSelect {
		return guidance.ToolQuery
	}
	return guidance.ToolWrite
}

// refusalOp is the op the guard's record_refusal accepts.
func refusalOp(op action.Op) action.Op {
	switch op {
	case action.OpSelect, action.OpInsert, action.OpUpdate, action.OpDelete:
		return op
	case action.OpMerge, action.OpOther:
		return action.OpOther
	}
	return action.OpOther
}

// checkArgs checks the parameters match the statement's placeholders and
// fit the guard's ledger limit.
func checkArgs(stmt action.Statement, params []any) error {
	if stmt.ParamCount != len(params) {
		return &guidance.ArgumentError{Message: fmt.Sprintf("the statement uses %d parameters ($1..$%d) but %d were given",
			stmt.ParamCount, stmt.ParamCount, len(params))}
	}
	raw, err := json.Marshal(params)
	if err != nil || len(raw) > maxParamsBytes {
		return &guidance.ArgumentError{Message: "params must encode to at most 64 KiB of JSON"}
	}
	return nil
}
