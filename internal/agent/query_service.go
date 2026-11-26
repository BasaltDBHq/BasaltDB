package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// RunInfo is a started run.
type RunInfo struct {
	RunID     uuid.UUID
	TaskID    uuid.UUID
	Intent    string
	StartedAt time.Time
	// Warnings are what the person should hear about the setup, with the
	// steps for it (GUARD_UPGRADE_AVAILABLE).
	Warnings []toolresult.Warning
}

// StartRun starts a run with intent. taskID joins a task another agent
// started; uuid.Nil starts a new task.
func (wc *Service) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	run, err := wc.startRun(ctx, intent, taskID)
	if err != nil {
		return RunInfo{}, err
	}
	run.Warnings = wc.upgrade.UpgradeWarnings(ctx)
	return run, nil
}

// startRun is StartRun without the setup warnings, for the run a write
// starts for itself.
func (wc *Service) startRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	if taskID == uuid.Nil {
		taskID = newID()
	}
	run := RunInfo{RunID: newID(), TaskID: taskID, Intent: intent, StartedAt: wc.core.Now().UTC()}
	if err := wc.store.Ledger.StartRun(ctx, action.Intent{RunID: run.RunID, TaskID: taskID, Text: intent}); err != nil {
		return RunInfo{}, err
	}
	return run, nil
}

// QueryParams are one query call's validated arguments.
type QueryParams struct {
	Request agentstore.Request
	RunID   uuid.UUID // uuid.Nil when the read is outside a run
}

// QueryOutcome is one recorded read.
type QueryOutcome struct {
	action.ReadResult
	ChangeID uuid.UUID
	Warnings []toolresult.Warning
}

// Query checks the request against the policy, runs it read-only within the limits
// and records the read with the version of each row it could identify. A
// refused or failed statement is recorded as a REFUSED change. A read that
// cannot be recorded is not returned: the ledger must know what the agent
// saw.
func (wc *Service) Query(ctx context.Context, p QueryParams) (QueryOutcome, error) {
	run, err := ledgersvc.FindRun(ctx, wc.store.Ledger, p.RunID)
	if err != nil {
		return QueryOutcome{}, err
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: run.Intent}
	start := wc.core.Now()
	stmt, err := wc.store.Language.Check(p.Request, action.ToolQuery)
	if err != nil {
		return QueryOutcome{}, wc.refused(ctx, in, stmt, p.Request, start, err)
	}
	res, err := wc.store.Data.Read(ctx, p.Request, stmt)
	if err != nil {
		return QueryOutcome{}, wc.refused(ctx, in, stmt, p.Request, start, err)
	}
	// The values of IDENTIFIER columns go in the dictionary before the rows
	// leave the engine (M5.1 plan, section 6). One that cannot be added
	// keeps the rows from the agent.
	if err := wc.pii.Observe(ctx, res.Columns, res.Rows); err != nil {
		wc.core.Log.Error("pii: the read's values could not be added to the dictionary; its rows are withheld", "err", err)
		// An engine failure, not the agent's SQL: INTERNAL even when a
		// Postgres error (a map reload) caused it. The cause is logged above.
		return QueryOutcome{}, &toolresult.ToolError{Code: guidance.CodeInternal, Message: "internal engine error"}
	}
	change, err := wc.store.Ledger.RecordRead(ctx, action.Read{
		RunID: run.ID, Statement: p.Request.Text, Params: p.Request.Params, Tables: stmt.Tables,
		Rows: len(res.Rows), Duration: res.Duration, Versions: res.Versions,
	})
	if err != nil {
		return QueryOutcome{}, fmt.Errorf("record read: %w", err)
	}
	return QueryOutcome{ReadResult: res, ChangeID: change, Warnings: wc.rlsWarnings(ctx, stmt.Tables, len(res.Rows))}, nil
}

// ListRuns returns one page of the agent's own runs with what each did.
func (wc *Service) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return wc.store.Ledger.ListRuns(ctx, p)
}

// recorded reports whether a failure is an action the ledger keeps as
// REFUSED: anything the policy, the guard or the database refused. Bad
// arguments, a missing run, and an unreachable database are not actions.
func recorded(code string) bool {
	switch code {
	case guidance.CodeInvalidArgument, guidance.CodeNotFound, guidance.CodeUnavailable, guidance.CodeInternal:
		return false
	}
	return true
}

// refused records a REFUSED change for err when it is an action the ledger
// keeps, with the op and resources of stmt (as much as the check
// classified), and returns err. A failure to record is logged; the agent
// still gets the original refusal.
func (wc *Service) refused(ctx context.Context, in action.Intent, stmt action.Statement, req agentstore.Request, start time.Time, err error) error {
	op := stmt.Op
	te := guidance.MessageTooLarge(actionTool(op), err, wc.core.Errors.ToolError(err))
	if !recorded(te.Code) {
		return err
	}
	r := action.Refusal{
		Intent: in, Op: refusalOp(op), Statement: req.Text, Params: req.Params,
		Code: te.Code, Reason: truncate(te.Message, maxReasonBytes), Duration: wc.core.Now().Sub(start),
		Resources: refusalResources(stmt),
	}
	if recErr := wc.recordRefusal(context.WithoutCancel(ctx), r); recErr != nil {
		wc.core.Log.Error("record refusal", "code", te.Code, "err", recErr)
	}
	return err
}

// recordRefusal records r. When that fails while r names resources, it
// records r once more naming none, so no name can keep a refusal out of
// the ledger, and logs the first failure as a warning.
func (wc *Service) recordRefusal(ctx context.Context, r action.Refusal) error {
	err := wc.store.Ledger.RecordRefusal(ctx, r)
	if err == nil || len(r.Resources) == 0 {
		return err
	}
	r.Resources = nil
	if retryErr := wc.store.Ledger.RecordRefusal(ctx, r); retryErr != nil {
		return errors.Join(err, retryErr)
	}
	wc.core.Log.Warn("record refusal: recorded without its resources", "code", r.Code, "err", err)
	return nil
}

// refusalResources are the resources a refusal records: a write's target
// first, as a write's own record names it, then the statement's other
// relations as the check lists them. The order matters: the change record
// names the first, so a write cannot pick its refusal's resource by naming
// another table that sorts earlier.
func refusalResources(stmt action.Statement) []string {
	if stmt.Target == "" {
		return stmt.Tables
	}
	out := make([]string, 0, len(stmt.Tables)+1)
	out = append(out, stmt.Target)
	for _, t := range stmt.Tables {
		if t != stmt.Target {
			out = append(out, t)
		}
	}
	return out
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func newID() uuid.UUID {
	return uuid.Must(uuid.NewV7()) //nolint:forbidigo // baseline: move to internal/lib/uniqueid
}
