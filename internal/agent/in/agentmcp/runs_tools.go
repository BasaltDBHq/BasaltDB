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
	Kind               string   `json:"kind"`
	RunID              string   `json:"runId"`
	TaskID             string   `json:"taskId"`
	Intent             string   `json:"intent"`
	StartedAt          string   `json:"startedAt"`
	LastChangeAt       string   `json:"lastChangeAt,omitempty"`
	Applied            int      `json:"applied"`
	Held               int      `json:"held"`
	Refused            int      `json:"refused"`
	Reverted           int      `json:"reverted"`
	Reads              int      `json:"reads"`
	RowsWritten        int      `json:"rowsWritten"`
	Resources          []string `json:"resources"`
	ResourcesTruncated bool     `json:"resourcesTruncated,omitempty"`
}

func runSummaryFromDomain(r action.RunSummary) runSummaryDTO {
	out := runSummaryDTO{
		Kind: action.RunItemRun, RunID: r.ID.String(), TaskID: r.TaskID.UUID.String(), Intent: r.Intent, StartedAt: guidance.TimeText(r.StartedAt),
		Applied: r.Applied, Held: r.Held, Refused: r.Refused, Reverted: r.Reverted, Reads: r.Reads,
		RowsWritten: r.RowsWritten, Resources: r.Resources, ResourcesTruncated: r.ResourcesTruncated,
	}
	if r.LastChangeAt != nil {
		out.LastChangeAt = guidance.TimeText(*r.LastChangeAt)
	}
	if out.Resources == nil {
		out.Resources = []string{}
	}
	return out
}

// revertSummaryDTO is a list_runs item of kind REVERT.
type revertSummaryDTO struct {
	Kind     string `json:"kind"`
	RevertID string `json:"revertId"`
	Scope    string `json:"scope"`
	ScopeID  string `json:"scopeId"`
	SignedAt string `json:"signedAt"`
	Restored int    `json:"restored"`
	Skipped  int    `json:"skipped"`
	Intent   string `json:"intent"`
}

// looseReadsDTO is a list_runs item of kind LOOSE_READS.
type looseReadsDTO struct {
	Kind               string   `json:"kind"`
	From               string   `json:"from"`
	To                 string   `json:"to"`
	Reads              int      `json:"reads"`
	Resources          []string `json:"resources"`
	ResourcesTruncated bool     `json:"resourcesTruncated,omitempty"`
}

func revertSummaryFromDomain(r action.RevertSummary) revertSummaryDTO {
	return revertSummaryDTO{
		Kind: action.RunItemRevert, RevertID: r.ID.String(), Scope: r.Scope, ScopeID: r.ScopeID.UUID.String(),
		SignedAt: guidance.TimeText(r.SignedAt), Restored: r.Restored, Skipped: r.Skipped, Intent: r.Intent,
	}
}

func looseReadsFromDomain(l action.LooseReads) looseReadsDTO {
	out := looseReadsDTO{
		Kind: action.RunItemLooseReads, From: guidance.TimeText(l.From), To: guidance.TimeText(l.To), Reads: l.Reads,
		Resources: l.Resources, ResourcesTruncated: l.ResourcesTruncated,
	}
	if out.Resources == nil {
		out.Resources = []string{}
	}
	return out
}

func runListItemFromDomain(it action.RunListItem) any {
	switch it.Kind {
	case action.RunItemRevert:
		return revertSummaryFromDomain(it.Revert)
	case action.RunItemLooseReads:
		return looseReadsFromDomain(it.Loose)
	}
	return runSummaryFromDomain(it.Run)
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
	items := make([]any, 0, len(page.Items))
	for _, it := range page.Items {
		items = append(items, runListItemFromDomain(it))
	}
	return pagination.ToMCP(pagination.Page[any]{Items: items, NextCursor: page.NextCursor}), nil
}
