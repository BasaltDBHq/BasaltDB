package agentmcp

import (
	"context"
	"encoding/json"
	"fmt"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Agent is the agent use case as its tools call it: runs, reads, writes and
// the database's description, the family of the store it serves, and
// describe's own error mapping.
type Agent interface {
	Family() agentstore.Family
	StartRun(ctx context.Context, intent string, taskID uuid.UUID) (agentsvc.RunInfo, error)
	Query(ctx context.Context, p agentsvc.QueryParams) (agentsvc.QueryOutcome, error)
	Write(ctx context.Context, p agentsvc.WriteParams) (agentsvc.WriteOutcome, error)
	ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error)
	DescribeOverview(ctx context.Context) (agentsvc.Overview, error)
	DescribeResource(ctx context.Context, resource, ifFingerprint string) (agentsvc.Resource, error)
	DescribeSearch(ctx context.Context, p agentsvc.DescribeSearchParams) (pagination.Page[agentsvc.SearchItem], error)
	DescribeError(err error) error
}

// RunStartTools are the tools that start a run. mount lists a tool under its
// contract, around Wrap; the tool list's composer supplies it.
// Handlers parse, validate, make one service call and render.
func RunStartTools(svc Agent, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc}
	return []mcpserver.Tool{mount("run_start", h.runStart)}
}

type handlers struct {
	svc Agent
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
	run, err := h.svc.StartRun(ctx, args.Intent, uniqueid.Optional(args.TaskID))
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

func queryResultFromDomain(r agentsvc.QueryOutcome) queryResult {
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
	res, err := h.svc.Query(ctx, agentsvc.QueryParams{Request: agentstore.Request{Text: args.SQL, Params: params}, RunID: uniqueid.Optional(args.RunID)})
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
