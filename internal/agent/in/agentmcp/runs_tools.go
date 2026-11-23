package agentmcp

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// --- list_runs ---

// runSummaryDTO is one list_runs item (api/mcp/tools/list_runs.json).
type runSummaryDTO struct {
	RunID           string   `json:"runId"`
	TaskID          string   `json:"taskId"`
	Intent          string   `json:"intent"`
	StartedAt       string   `json:"startedAt"`
	LastChangeAt    string   `json:"lastChangeAt,omitempty"`
	Applied         int      `json:"applied"`
	Held            int      `json:"held"`
	Refused         int      `json:"refused"`
	Reverted        int      `json:"reverted"`
	Reads           int      `json:"reads"`
	RowsWritten     int      `json:"rowsWritten"`
	Tables          []string `json:"tables"`
	TablesTruncated bool     `json:"tablesTruncated,omitempty"`
}

func runSummaryFromDomain(r action.RunSummary) runSummaryDTO {
	out := runSummaryDTO{
		RunID: r.ID.String(), TaskID: r.TaskID.UUID.String(), Intent: r.Intent, StartedAt: guidance.TimeText(r.StartedAt),
		Applied: r.Applied, Held: r.Held, Refused: r.Refused, Reverted: r.Reverted, Reads: r.Reads,
		RowsWritten: r.RowsWritten, Tables: r.Tables, TablesTruncated: r.TablesTruncated,
	}
	if r.LastChangeAt != nil {
		out.LastChangeAt = guidance.TimeText(*r.LastChangeAt)
	}
	if out.Tables == nil {
		out.Tables = []string{}
	}
	return out
}

// listRuns serves list_runs. Its arguments are action.RunListParams itself
// (pagination.Params plus the time range), decoded strictly and validated
// by its tags.
func (h handlers) listRuns(ctx context.Context, raw json.RawMessage) (any, error) {
	var params action.RunListParams
	if err := guidance.DecodeArgs(raw, &params); err != nil {
		return nil, err
	}
	params.ApplyDefaultsAndClamp()
	page, err := h.svc.ListRuns(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]runSummaryDTO, 0, len(page.Items))
	for _, r := range page.Items {
		items = append(items, runSummaryFromDomain(r))
	}
	return pagination.ToMCP(pagination.Page[runSummaryDTO]{Items: items, NextCursor: page.NextCursor}), nil
}

// RunTools are the tools that list the agent's runs.
func RunTools(svc Agent, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool) []guidance.Tool {
	h := handlers{svc: svc}
	return []guidance.Tool{
		mount("list_runs", h.listRuns),
	}
}
