package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// StatusApplied is the status of an applied write.
const StatusApplied = "APPLIED"

// Tools returns the MCP tools served to one agent: every contract in api/mcp
// that is IMPLEMENTED, each listed with the contract's description and input
// schema. Handlers parse, validate, make one service call and render.
func Tools(svc *Service) []mcp.Tool {
	if svc == nil {
		panic("agent: service required")
	}
	h := handlers{svc: svc, log: svc.Log}
	return []mcp.Tool{
		contractTool("run_start", h.wrap("run_start", h.runStart)),
		contractTool("query", h.wrap("query", h.query)),
		contractTool("write", h.wrap("write", h.write)),
		contractTool("run_history", h.wrap("run_history", h.runHistory)),
		contractTool("list_pending", h.wrap("list_pending", h.listPending)),
		contractTool("preview_revert", h.wrap("preview_revert", h.previewRevert)),
		contractTool("revert_plan", h.wrap("revert_plan", h.revertPlan)),
		contractTool("apply_revert_batch", h.wrap("apply_revert_batch", h.applyRevertBatch)),
	}
}

// contractTool builds a tool from its contract. A missing contract is a
// build defect: the contract test keeps served tools and contracts aligned.
func contractTool(name string, call func(context.Context, json.RawMessage) (any, error)) mcp.Tool {
	c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
	if !ok {
		panic("agent: no contract for tool " + name)
	}
	return mcp.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: call}
}

type handlers struct {
	svc *Service
	log *slog.Logger
}

// wrap maps every error to the contract's error body, logging the ones that
// are the engine's fault.
func (h handlers) wrap(tool string, call func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, args json.RawMessage) (any, error) {
		out, err := call(ctx, args)
		if err == nil {
			return out, nil
		}
		te := ToolError(err)
		if te.Code == CodeInternal || te.Code == CodeUnavailable {
			h.log.Error("tool failed", "tool", tool, "code", te.Code, "err", err)
		}
		return nil, te
	}
}

var validate = validator.New(validator.WithRequiredStructEnabled())

// decodeArgs decodes tool arguments strictly: unknown arguments are refused,
// numbers keep their text, and struct tags are validated.
func decodeArgs(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return &ArgumentError{Message: fmt.Sprintf("invalid arguments: %v", err)}
	}
	if err := validate.Struct(v); err != nil {
		return &ArgumentError{Message: fmt.Sprintf("invalid arguments: %v", err)}
	}
	return nil
}

// optionalID parses an optional uuid argument already validated by tags.
func optionalID(s string) uuid.UUID {
	if s == "" {
		return uuid.Nil
	}
	return uuid.MustParse(s)
}

func timeText(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// --- run_start ---

// runStartArgs is the run_start tool's input (api/mcp/tools/run_start.json).
type runStartArgs struct {
	Intent string `json:"intent" validate:"required,max=500"`
	TaskID string `json:"taskId" validate:"omitempty,uuid"`
}

type runStartResult struct {
	RunID     string `json:"runId"`
	TaskID    string `json:"taskId"`
	Intent    string `json:"intent"`
	StartedAt string `json:"startedAt"`
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
	return runStartResult{RunID: run.RunID.String(), TaskID: run.TaskID.String(), Intent: run.Intent, StartedAt: timeText(run.StartedAt)}, nil
}

// --- query ---

// queryArgs is the query tool's input (api/mcp/tools/query.json).
type queryArgs struct {
	SQL    string `json:"sql" validate:"required,max=16384"`
	Params []any  `json:"params" validate:"max=1000"`
	RunID  string `json:"runId" validate:"omitempty,uuid"`
}

type queryResult struct {
	ChangeID   string           `json:"changeId"`
	Columns    []columnDTO      `json:"columns"`
	Rows       []map[string]any `json:"rows"`
	RowCount   int              `json:"rowCount"`
	DurationMs int64            `json:"durationMs"`
}

type columnDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func queryResultFromDomain(r QueryOutcome) queryResult {
	return queryResult{
		ChangeID: r.ChangeID.String(), Columns: columnsDTO(r.Columns), Rows: r.Rows, RowCount: len(r.Rows),
		DurationMs: r.Duration.Milliseconds(),
	}
}

func columnsDTO(cols []agentdb.Column) []columnDTO {
	out := make([]columnDTO, 0, len(cols))
	for _, c := range cols {
		out = append(out, columnDTO(c))
	}
	return out
}

func (h handlers) query(ctx context.Context, raw json.RawMessage) (any, error) {
	var args queryArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params, err := agentdb.ParamValues(args.Params)
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
	ApprovalID string `json:"approvalId" validate:"required_with=Approval,omitempty,uuid"`
	Approval   string `json:"approval" validate:"omitempty,max=8192"`
	// WaitForApproval is seconds to wait for a held write's approval
	// (CONTRACT.md, Approvals, Waiting write); nil means the default.
	WaitForApproval *int `json:"waitForApproval" validate:"omitempty,min=0,max=110"`
}

type writeResult struct {
	ChangeID   string           `json:"changeId"`
	RunID      string           `json:"runId"`
	Op         string           `json:"op"`
	Rows       int              `json:"rows"`
	DurationMs int64            `json:"durationMs"`
	Status     string           `json:"status"`
	Returning  []map[string]any `json:"returning,omitempty"`
}

func writeResultFromDomain(o WriteOutcome) writeResult {
	return writeResult{
		ChangeID: o.ChangeID.String(), RunID: o.RunID.String(), Op: string(o.Op), Rows: o.Rows,
		DurationMs: o.Duration.Milliseconds(), Status: StatusApplied, Returning: o.Returning,
	}
}

func (h handlers) write(ctx context.Context, raw json.RawMessage) (any, error) {
	var args writeArgs
	if err := decodeArgs(raw, &args); err != nil {
		// An empty or missing intent is the contract's INTENT_REQUIRED.
		if intentMissing(raw) {
			return nil, &mcp.ToolError{Code: CodeIntentRequired, Message: "write needs an intent: why this change is made"}
		}
		return nil, err
	}
	params, err := agentdb.ParamValues(args.Params)
	if err != nil {
		return nil, &ArgumentError{Message: err.Error()}
	}
	out, err := h.svc.Write(ctx, WriteParams{
		SQL: args.SQL, Params: params, Intent: args.Intent, RunID: optionalID(args.RunID),
		ApprovalID: optionalID(args.ApprovalID), Approval: args.Approval,
	})
	if err != nil {
		return nil, err
	}
	return writeResultFromDomain(out), nil
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
	params := ledger.ChangeListParams{Params: args.Params, RunID: uuid.MustParse(args.RunID)}
	params.ApplyDefaultsAndClamp()
	hist, err := h.svc.History(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]ledger.Record, 0, len(hist.Page.Items))
	for _, ch := range hist.Page.Items {
		items = append(items, ledger.RecordFromDomain(ch, hist.Rows[ch.ID]))
	}
	return pagination.ToMCP(pagination.Page[ledger.Record]{Items: items, NextCursor: hist.Page.NextCursor}), nil
}
