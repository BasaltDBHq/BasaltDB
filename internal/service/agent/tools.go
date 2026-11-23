package agent

import (
	"context"
	"encoding/json"
	"fmt"

	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Tools returns the MCP tools served to one agent: every contract in api/mcp
// that is IMPLEMENTED, each listed with the contract's description and
// input schema, and query and write only for a store that speaks SQL
// (CONTRACT.md, Stores). Handlers parse, validate, make one service call
// and render.
func Tools(svc *Service) []guidance.Tool {
	if svc == nil {
		panic("agent: service required")
	}
	h := handlers{svc: svc}
	tools := h.runStartTools()
	if speaksSQL(svc.deps.Core.Store.Kind()) {
		tools = append(tools, h.writeTools()...)
	}
	for _, list := range [][]guidance.Tool{
		h.runTools(), h.approvalTools(), h.revertTools(), h.pluginTools(), h.describeTools(), h.statusTools(),
	} {
		tools = append(tools, list...)
	}
	return tools
}

// runStartTools are the tools that start a run.
func (h handlers) runStartTools() []guidance.Tool {
	return []guidance.Tool{contractTool("run_start", h.wrap("run_start", h.runStart))}
}

// speaksSQL reports whether a store of kind runs SQL: the query and write
// tools are served for it, in its dialect.
func speaksSQL(kind action.StoreKind) bool {
	return kind == action.StorePostgres || kind == action.StoreMySQL
}

// contractTool builds a tool from its contract. A missing contract is a
// build defect: the contract test keeps served tools and contracts aligned.
func contractTool(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool {
	c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
	if !ok {
		panic("agent: no contract for tool " + name)
	}
	return guidance.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: call}
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
				return nil, linksvc.DevLocalError(te)
			}
			return nil, te
		}
		out, err := h.admitted(ctx, tool, args, call)
		switch {
		case err == nil && h.svc.deps.Status.DevLocalPages:
			return linksvc.DevLocalResult(out)
		case err == nil:
			return out, nil
		}
		te := h.svc.Failure(tool, guidance.CallArgs(args), err)
		if h.svc.deps.Status.DevLocalPages {
			return nil, linksvc.DevLocalError(te)
		}
		return nil, te
	}
}

func (h handlers) admitted(ctx context.Context, tool string, args json.RawMessage, call func(context.Context, json.RawMessage) (any, error)) (any, error) {
	// status always answers; confirm_database answers INVALID_ARGUMENT
	// here, where no connect-only database waits (ConnectOnly serves it
	// while one does).
	if tool == guidance.ToolStatus || tool == guidance.ToolConfirmDatabase {
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
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	run, err := h.svc.StartRun(ctx, args.Intent, optionalID(args.TaskID))
	if err != nil {
		return nil, err
	}
	return runStartResult{RunID: run.RunID.String(), TaskID: run.TaskID.String(), Intent: run.Intent, StartedAt: guidance.TimeText(run.StartedAt), Warnings: run.Warnings}, nil
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
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params, err := paramValues(args.Params)
	if err != nil {
		return nil, &guidance.ArgumentError{Message: err.Error()}
	}
	res, err := h.svc.Query(ctx, QueryParams{SQL: args.SQL, Params: params, RunID: optionalID(args.RunID)})
	if err != nil {
		return nil, err
	}
	return queryResultFromDomain(res), nil
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

func (h handlers) runHistory(ctx context.Context, raw json.RawMessage) (any, error) {
	var args ledgersvc.RunHistoryArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
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
