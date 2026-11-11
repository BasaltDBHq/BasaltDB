package agent

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// --- list_pending ---

// listPendingArgs is the list_pending tool's input
// (api/mcp/tools/list_pending.json).
type listPendingArgs struct {
	pagination.Params
	RunID  string `json:"runId" validate:"omitempty,uuid"`
	Status string `json:"status" validate:"omitempty,oneof=PENDING APPROVED"`
}

// pendingDTO is one item of list_pending's output.
type pendingDTO struct {
	ApprovalID      string          `json:"approvalId"`
	RunID           string          `json:"runId"`
	TaskID          string          `json:"taskId,omitempty"`
	Intent          string          `json:"intent"`
	Statement       string          `json:"statement"`
	Params          json.RawMessage `json:"params,omitempty"`
	AssignedColumns []string        `json:"assignedColumns"`
	Rows            int             `json:"rows"`
	Status          string          `json:"status"`
	CreatedAt       string          `json:"createdAt"`
	ExpiresAt       string          `json:"expiresAt"`
	ApprovalURL     string          `json:"approvalUrl"`
	ApproveCommand  string          `json:"approveCommand"`
	Headline        string          `json:"headline"`
	PersonMessage   string          `json:"personMessage"`
}

func pendingFromDomain(p PendingItem) pendingDTO {
	d := pendingDTO{
		ApprovalID: p.ID.String(), RunID: p.RunID.String(), Intent: p.Intent, Statement: p.Statement,
		Params: p.Params, AssignedColumns: p.Assigned, Rows: p.Rows, Status: p.Status,
		CreatedAt: timeText(p.CreatedAt), ExpiresAt: timeText(p.ExpiresAt), ApprovalURL: p.Notice.ApprovalURL, ApproveCommand: p.Notice.ApproveCommand,
		Headline: p.Notice.Headline, PersonMessage: p.Notice.PersonMessage,
	}
	if p.TaskID.Valid {
		d.TaskID = p.TaskID.UUID.String()
	}
	return d
}

func (h handlers) listPending(ctx context.Context, raw json.RawMessage) (any, error) {
	var args listPendingArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params := ledger.ApprovalListParams{Params: args.Params, RunID: optionalID(args.RunID), Status: args.Status}
	params.ApplyDefaultsAndClamp()
	page, err := h.svc.ListPending(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]pendingDTO, 0, len(page.Items))
	for _, p := range page.Items {
		items = append(items, pendingFromDomain(p))
	}
	return pagination.ToMCP(pagination.Page[pendingDTO]{Items: items, NextCursor: page.NextCursor}), nil
}
