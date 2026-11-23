package agent

import (
	"context"
	"encoding/json"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// --- list_pending ---

// listPendingArgs is the list_pending tool's input
// (api/mcp/tools/list_pending.json).
type listPendingArgs struct {
	pagination.Params
	Kind   string `json:"kind" validate:"omitempty,oneof=APPROVAL REVERT"`
	RunID  string `json:"runId" validate:"omitempty,uuid"`
	Status string `json:"status" validate:"omitempty,oneof=PENDING APPROVED APPLYING"`
	// ReissueLink issues each item a new short link (CONTRACT.md, Link
	// secrets).
	ReissueLink bool `json:"reissueLink"`
}

// pendingDTO is one item of list_pending's output.
type pendingDTO struct {
	Kind            string                `json:"kind"`
	ApprovalID      string                `json:"approvalId"`
	RunID           string                `json:"runId"`
	TaskID          string                `json:"taskId,omitempty"`
	Intent          string                `json:"intent"`
	Statement       string                `json:"statement,omitempty"`
	Params          json.RawMessage       `json:"params,omitempty"`
	AssignedColumns []string              `json:"assignedColumns"`
	Rows            int                   `json:"rows"`
	Status          string                `json:"status"`
	CreatedAt       string                `json:"createdAt"`
	ExpiresAt       string                `json:"expiresAt"`
	ApprovalURL     string                `json:"approvalUrl"`
	RequestFile     *links.RequestFile    `json:"requestFile,omitempty"`
	Headline        string                `json:"headline"`
	PersonMessage   string                `json:"personMessage"`
	NextSteps       []toolresult.NextStep `json:"nextSteps,omitempty"`
	Links           []toolresult.Link     `json:"links,omitempty"`
	// LargeValues names the statement or params left out (CONTRACT.md,
	// Large values).
	LargeValues []largevalue.Entry `json:"largeValues,omitempty"`
}

func pendingFromDomain(p PendingItem) pendingDTO {
	d := pendingDTO{
		Kind:       guidance.KindApproval,
		ApprovalID: p.ID.String(), RunID: p.RunID.String(), Intent: p.Intent, Statement: p.Statement,
		Params: p.Params, AssignedColumns: p.Assigned, Rows: p.Rows, Status: p.Status,
		CreatedAt: guidance.TimeText(p.CreatedAt), ExpiresAt: guidance.TimeText(p.ExpiresAt), ApprovalURL: p.Notice.ApprovalURL, RequestFile: p.Notice.RequestFile,
		Headline: p.Notice.Headline, PersonMessage: p.PersonMessage, Links: p.Links, NextSteps: p.NextSteps,
		LargeValues: p.LargeValues,
	}
	if p.TaskID.Valid {
		d.TaskID = p.TaskID.UUID.String()
	}
	return d
}

// pendingRevertDTO is a list_pending revert item (list_pending.json,
// kind REVERT). A widened revert has no scope and no link (RS-5).
type pendingRevertDTO struct {
	Kind          string                `json:"kind"`
	RevertID      string                `json:"revertId"`
	Status        string                `json:"status"`
	Scope         string                `json:"scope,omitempty"`
	ScopeID       string                `json:"scopeId,omitempty"`
	Intent        string                `json:"intent"`
	Rows          int                   `json:"rows"`
	Skipped       int                   `json:"skipped"`
	Batched       bool                  `json:"batched"`
	Widened       bool                  `json:"widened"`
	CreatedAt     string                `json:"createdAt"`
	ExpiresAt     string                `json:"expiresAt"`
	ApplyBy       string                `json:"applyBy,omitempty"`
	Progress      *revertProgressDTO    `json:"progress,omitempty"`
	Headline      string                `json:"headline"`
	RevertURL     string                `json:"revertUrl,omitempty"`
	RequestFile   *links.RequestFile    `json:"requestFile,omitempty"`
	PersonMessage string                `json:"personMessage"`
	Links         []toolresult.Link     `json:"links,omitempty"`
	NextSteps     []toolresult.NextStep `json:"nextSteps,omitempty"`
}

func pendingRevertFromDomain(p revertsvc.PendingRevert) pendingRevertDTO {
	d := pendingRevertDTO{
		Kind: guidance.KindRevert, RevertID: p.ID.String(), Status: p.Status, Intent: p.Intent, Rows: p.Rows, Skipped: p.Skipped,
		Batched: p.Batched, Widened: p.Widened, CreatedAt: guidance.TimeText(p.CreatedAt), ExpiresAt: guidance.TimeText(p.ExpiresAt),
		Headline: p.Headline, RevertURL: p.RevertURL, RequestFile: p.RequestFile, PersonMessage: p.PersonMessage, Links: p.Links, NextSteps: p.NextSteps,
	}
	if !p.Widened {
		d.Scope, d.ScopeID = p.Scope, p.ScopeID.String()
	}
	if p.ApplyBy != nil {
		d.ApplyBy = guidance.TimeText(*p.ApplyBy)
	}
	if p.Batched && p.SignedAt != nil {
		d.Progress = &revertProgressDTO{Restored: p.Progress.Restored, Skipped: p.Progress.Skipped, Pending: p.Progress.Pending, Batches: p.Batches}
	}
	return d
}

func (h handlers) listPending(ctx context.Context, raw json.RawMessage) (any, error) {
	var args listPendingArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params := PendingParams{Params: args.Params, Kind: args.Kind, RunID: optionalID(args.RunID), Status: args.Status, Reissue: args.ReissueLink}
	params.ApplyDefaultsAndClamp()
	page, err := h.svc.ListPending(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(page.Items))
	for _, e := range page.Items {
		if e.Approval != nil {
			items = append(items, pendingFromDomain(*e.Approval))
			continue
		}
		items = append(items, pendingRevertFromDomain(*e.Revert))
	}
	return pagination.ToMCP(pagination.Page[any]{Items: items, NextCursor: page.NextCursor}), nil
}

// approvalTools are the tools that read held writes.
func (h handlers) approvalTools() []guidance.Tool {
	return []guidance.Tool{
		contractTool("list_pending", h.wrap("list_pending", h.listPending)),
	}
}
