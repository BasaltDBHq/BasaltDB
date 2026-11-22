package agent

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
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
		RunID: r.ID.String(), TaskID: r.TaskID.UUID.String(), Intent: r.Intent, StartedAt: timeText(r.StartedAt),
		Applied: r.Applied, Held: r.Held, Refused: r.Refused, Reverted: r.Reverted, Reads: r.Reads,
		RowsWritten: r.RowsWritten, Tables: r.Tables, TablesTruncated: r.TablesTruncated,
	}
	if r.LastChangeAt != nil {
		out.LastChangeAt = timeText(*r.LastChangeAt)
	}
	if out.Tables == nil {
		out.Tables = []string{}
	}
	return out
}

// listRuns serves list_runs. Its arguments are ledger.RunListParams itself
// (pagination.Params plus the time range), decoded strictly and validated
// by its tags.
func (h handlers) listRuns(ctx context.Context, raw json.RawMessage) (any, error) {
	var params ledger.RunListParams
	if err := decodeArgs(raw, &params); err != nil {
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
