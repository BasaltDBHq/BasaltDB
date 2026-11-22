package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// StatusApplied is the status of an applied write.
const StatusApplied = "APPLIED"

// Tools returns the MCP tools served to one agent: every contract in api/mcp
// that is IMPLEMENTED, each listed with the contract's description and
// input schema, and query and write only for a store that speaks SQL
// (CONTRACT.md, Stores). Handlers parse, validate, make one service call
// and render.
func Tools(svc *Service) []Tool {
	if svc == nil {
		panic("agent: service required")
	}
	h := handlers{svc: svc}
	tools := []Tool{contractTool("run_start", h.wrap("run_start", h.runStart))}
	if speaksSQL(svc.deps.Core.Store.Kind()) {
		tools = append(tools,
			contractTool("query", h.wrap("query", h.query)),
			contractTool("write", h.wrap("write", h.write)))
	}
	return append(tools,
		contractTool("run_history", h.wrap("run_history", h.runHistory)),
		contractTool("list_runs", h.wrap("list_runs", h.listRuns)),
		contractTool("list_pending", h.wrap("list_pending", h.listPending)),
		contractTool("preview_revert", h.wrap("preview_revert", h.previewRevert)),
		contractTool("revert_plan", h.wrap("revert_plan", h.revertPlan)),
		contractTool("apply_revert_batch", h.wrap("apply_revert_batch", h.applyRevertBatch)),
		contractTool("request_revert", h.wrap("request_revert", h.requestRevert)),
		contractTool(toolRequestPlugin, h.wrap(toolRequestPlugin, h.requestPlugin)),
		contractTool(toolDescribe, h.wrap(toolDescribe, h.describe)),
		contractTool(toolStatus, h.wrap(toolStatus, h.status)),
		contractTool(toolConfirmDatabase, h.wrap(toolConfirmDatabase, h.confirmDatabase)),
	)
}

// speaksSQL reports whether a store of kind runs SQL: the query and write
// tools are served for it, in its dialect.
func speaksSQL(kind action.StoreKind) bool {
	return kind == action.StorePostgres || kind == action.StoreMySQL
}

// contractTool builds a tool from its contract. A missing contract is a
// build defect: the contract test keeps served tools and contracts aligned.
func contractTool(name string, call func(context.Context, json.RawMessage) (any, error)) Tool {
	c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
	if !ok {
		panic("agent: no contract for tool " + name)
	}
	return Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: call}
}

type handlers struct {
	svc *Service
}

// wrap admits the call (every tool but status, see Service.Admit) and maps
// every error to the contract's error body, logging the ones that are the
// engine's fault.
func (h handlers) wrap(tool string, call func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, args json.RawMessage) (any, error) {
		// Before anything else: the call is not admitted, decoded, recorded
		// or logged, and its arguments are not echoed into the error.
		if holdsAdminCredential(args) {
			te := h.svc.Failure(tool, nil, adminCredentialError())
			if h.svc.deps.Status.DevLocalPages {
				return nil, devLocalError(te)
			}
			return nil, te
		}
		out, err := h.admitted(ctx, tool, args, call)
		switch {
		case err == nil && h.svc.deps.Status.DevLocalPages:
			return devLocalResult(out)
		case err == nil:
			return out, nil
		}
		te := h.svc.Failure(tool, callArgs(args), err)
		if h.svc.deps.Status.DevLocalPages {
			return nil, devLocalError(te)
		}
		return nil, te
	}
}

func (h handlers) admitted(ctx context.Context, tool string, args json.RawMessage, call func(context.Context, json.RawMessage) (any, error)) (any, error) {
	// status always answers; confirm_database answers INVALID_ARGUMENT
	// here, where no connect-only database waits (ConnectOnly serves it
	// while one does).
	if tool == toolStatus || tool == toolConfirmDatabase {
		return call(ctx, args)
	}
	if err := h.svc.Admit(ctx); err != nil {
		return nil, err
	}
	return call(ctx, args)
}

// optionalID parses an optional uuid argument already validated by tags.
func optionalID(s string) uuid.UUID {
	if s == "" {
		return uuid.Nil
	}
	return uuid.MustParse(s)
}

// --- run_start ---

// runStartArgs is the run_start tool's input (api/mcp/tools/run_start.json).
type runStartArgs struct {
	Intent string `json:"intent" validate:"required,max=500"`
	TaskID string `json:"taskId" validate:"omitempty,uuid"`
}

type runStartResult struct {
	RunID     string               `json:"runId"`
	TaskID    string               `json:"taskId"`
	Intent    string               `json:"intent"`
	StartedAt string               `json:"startedAt"`
	Warnings  []toolresult.Warning `json:"warnings,omitempty"`
}

func (h handlers) runStart(ctx context.Context, raw json.RawMessage) (any, error) {
	var args runStartArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	run, err := h.svc.StartRun(ctx, args.Intent, optionalID(args.TaskID))
	if err != nil {
		return nil, err
	}
	return runStartResult{RunID: run.RunID.String(), TaskID: run.TaskID.String(), Intent: run.Intent, StartedAt: timeText(run.StartedAt), Warnings: run.Warnings}, nil
}

// --- query ---

// queryArgs is the query tool's input (api/mcp/tools/query.json).
type queryArgs struct {
	SQL    string `json:"sql" validate:"required,max=16384"`
	Params []any  `json:"params" validate:"max=1000"`
	RunID  string `json:"runId" validate:"omitempty,uuid"`
}

type queryResult struct {
	ChangeID   string               `json:"changeId"`
	Columns    []columnDTO          `json:"columns"`
	Rows       []map[string]any     `json:"rows"`
	RowCount   int                  `json:"rowCount"`
	DurationMs int64                `json:"durationMs"`
	Warnings   []toolresult.Warning `json:"warnings,omitempty"`
}

type columnDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func queryResultFromDomain(r QueryOutcome) queryResult {
	return queryResult{
		ChangeID: r.ChangeID.String(), Columns: columnsDTO(r.Columns), Rows: r.Rows, RowCount: len(r.Rows),
		DurationMs: r.Duration.Milliseconds(), Warnings: r.Warnings,
	}
}

func columnsDTO(cols []action.Column) []columnDTO {
	out := make([]columnDTO, 0, len(cols))
	for _, c := range cols {
		out = append(out, columnDTO{Name: c.Name, Type: c.Type})
	}
	return out
}

func (h handlers) query(ctx context.Context, raw json.RawMessage) (any, error) {
	var args queryArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params, err := paramValues(args.Params)
	if err != nil {
		return nil, &ArgumentError{Message: err.Error()}
	}
	res, err := h.svc.Query(ctx, QueryParams{SQL: args.SQL, Params: params, RunID: optionalID(args.RunID)})
	if err != nil {
		return nil, err
	}
	return queryResultFromDomain(res), nil
}

// --- write ---

// writeArgs is the write tool's input (api/mcp/tools/write.json).
type writeArgs struct {
	SQL        string `json:"sql" validate:"required,max=16384"`
	Params     []any  `json:"params" validate:"max=1000"`
	Intent     string `json:"intent" validate:"required,max=500"`
	RunID      string `json:"runId" validate:"omitempty,uuid"`
	ApprovalID string `json:"approvalId" validate:"omitempty,uuid"`
	// WaitForApproval is seconds to wait for a held write's approval
	// (CONTRACT.md, Approvals, Waiting write); nil means the default.
	WaitForApproval *int `json:"waitForApproval" validate:"omitempty,min=0,max=110"`
}

type writeResult struct {
	ChangeID   string               `json:"changeId"`
	RunID      string               `json:"runId"`
	Op         string               `json:"op"`
	Rows       int                  `json:"rows"`
	DurationMs int64                `json:"durationMs"`
	Status     string               `json:"status"`
	Returning  []map[string]any     `json:"returning,omitempty"`
	Warnings   []toolresult.Warning `json:"warnings,omitempty"`
	// PersonMessage, Receipt and NoReceipt: a held write's receipt
	// (CONTRACT.md, Vault channel, Receipts).
	PersonMessage string `json:"personMessage,omitempty"`
	Receipt       string `json:"receipt,omitempty"`
	NoReceipt     string `json:"noReceipt,omitempty"`
}

func writeResultFromDomain(o WriteOutcome) writeResult {
	out := writeResult{
		ChangeID: o.ChangeID.String(), RunID: o.RunID.String(), Op: string(o.Op), Rows: o.Rows,
		DurationMs: o.Duration.Milliseconds(), Status: StatusApplied, Returning: o.Returning, Warnings: o.Warnings,
	}
	if o.Receipt != nil {
		out.PersonMessage, out.Receipt, out.NoReceipt = o.Receipt.Line, o.Receipt.Token, o.Receipt.Missing
	}
	return out
}

func (h handlers) write(ctx context.Context, raw json.RawMessage) (any, error) {
	var args writeArgs
	if err := decodeArgs(raw, &args); err != nil {
		// An empty or missing intent is the contract's INTENT_REQUIRED.
		if intentMissing(raw) {
			return nil, &toolresult.ToolError{Code: CodeIntentRequired, Message: "write needs an intent: why this change is made"}
		}
		return nil, err
	}
	params, err := paramValues(args.Params)
	if err != nil {
		return nil, &ArgumentError{Message: err.Error()}
	}
	out, err := h.svc.Write(ctx, WriteParams{
		SQL: args.SQL, Params: params, Intent: args.Intent, RunID: optionalID(args.RunID),
		ApprovalID: optionalID(args.ApprovalID), Wait: args.wait(),
	})
	if err != nil {
		return nil, err
	}
	return writeResultFromDomain(out), nil
}

// wait is waitForApproval with its default (CONTRACT.md, Waiting write):
// none on a new write, so the agent gets the link at once, and
// DefaultApprovalWait on a repeat with approvalId.
func (a writeArgs) wait() time.Duration {
	if a.WaitForApproval != nil {
		return time.Duration(*a.WaitForApproval) * time.Second
	}
	if a.ApprovalID == "" {
		return 0
	}
	return DefaultApprovalWait
}

func intentMissing(raw json.RawMessage) bool {
	var probe struct {
		Intent *string `json:"intent"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Intent == nil || *probe.Intent == ""
}

// --- run_history ---

// runHistoryArgs is the run_history tool's input
// (api/mcp/tools/run_history.json): the list params struct embeds
// pagination.Params, as every list does.
type runHistoryArgs struct {
	pagination.Params
	RunID string `json:"runId" validate:"required,uuid"`
}

func (h handlers) runHistory(ctx context.Context, raw json.RawMessage) (any, error) {
	var args runHistoryArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params := action.ChangeListParams{Params: args.Params, RunID: uuid.MustParse(args.RunID)}
	params.ApplyDefaultsAndClamp()
	hist, err := h.svc.History(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(hist.Page.Items))
	for _, ch := range hist.Page.Items {
		items = append(items, h.svc.deps.Write.Record(ch, hist.Rows[ch.ID]))
	}
	return pagination.ToMCP(pagination.Page[any]{Items: items, NextCursor: hist.Page.NextCursor}), nil
}

// paramValues converts JSON-decoded parameters for the store's driver: integral numbers
// become int64 and other numbers float64, so an id passed as 4211 binds to
// an integer column.
func paramValues(params []any) ([]any, error) {
	out := make([]any, 0, len(params))
	for i, p := range params {
		switch p.(type) {
		case map[string]any, []any:
			return nil, fmt.Errorf("params[%d]: must be a string, number, boolean or null", i)
		}
		n, ok := p.(json.Number)
		if !ok {
			out = append(out, p)
			continue
		}
		if v, err := n.Int64(); err == nil {
			out = append(out, v)
			continue
		}
		v, err := n.Float64()
		if err != nil {
			return nil, fmt.Errorf("params[%d]: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}
