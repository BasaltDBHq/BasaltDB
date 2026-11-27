// Package approvalmcp serves the approval tools over MCP: list_pending, the
// held writes and open reverts of the agent. Handlers parse, validate, make
// one call to the approval use case and render.
package approvalmcp

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Pending is the approval use case as the approval tools call it.
type Pending interface {
	ListPending(ctx context.Context, p approvalsvc.PendingParams) (pagination.Page[approvalsvc.PendingEntry], error)
}

// Withdrawer withdraws the agent's own held write, revert or plugin
// approval while it waits for the person (the withdraw tool).
type Withdrawer interface {
	Withdraw(ctx context.Context, p approvalsvc.WithdrawParams) (approvalsvc.WithdrawResult, error)
}

type handlers struct {
	svc      Pending
	withdraw Withdrawer
}

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
	Kind           string                `json:"kind"`
	ApprovalID     string                `json:"approvalId"`
	RunID          string                `json:"runId"`
	TaskID         string                `json:"taskId,omitempty"`
	Intent         string                `json:"intent"`
	Request        pendingRequestDTO     `json:"request"`
	AssignedFields []string              `json:"assignedFields"`
	Rows           int                   `json:"rows"`
	Status         string                `json:"status"`
	CreatedAt      string                `json:"createdAt"`
	ExpiresAt      string                `json:"expiresAt"`
	ApprovalURL    string                `json:"approvalUrl"`
	RequestFile    *links.RequestFile    `json:"requestFile,omitempty"`
	Headline       string                `json:"headline"`
	PersonMessage  string                `json:"personMessage"`
	NextSteps      []toolresult.NextStep `json:"nextSteps,omitempty"`
	Links          []toolresult.Link     `json:"links,omitempty"`
	// LargeValues names the statement or params left out (CONTRACT.md,
	// Large values).
	LargeValues []largevalue.Entry `json:"largeValues,omitempty"`
}

// pendingRequestDTO is a held write's request by family (CONTRACT.md,
// Stores, Request families), as the approval binds it: for SQL the
// statement and its params, either absent when left out as a large value.
type pendingRequestDTO struct {
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params,omitempty"`
	Statement string          `json:"statement,omitempty"`
}

func pendingFromDomain(p approvalsvc.PendingItem) pendingDTO {
	d := pendingDTO{
		Kind:       guidance.KindApproval,
		ApprovalID: p.ID.String(), RunID: p.RunID.String(), Intent: p.Intent,
		Request:        pendingRequestDTO{Kind: p.Request.Kind, Params: p.Request.Params, Statement: p.Request.Text},
		AssignedFields: p.Assigned, Rows: p.Rows, Status: p.Status,
		CreatedAt: guidance.TimeText(p.CreatedAt), ExpiresAt: guidance.TimeText(p.ExpiresAt), ApprovalURL: p.Notice.ApprovalURL, RequestFile: p.Notice.RequestFile,
		Headline: p.Notice.Headline, PersonMessage: p.PersonMessage, Links: p.Links, NextSteps: p.NextSteps,
		LargeValues: p.LargeValues,
	}
	if p.TaskID.Valid {
		d.TaskID = p.TaskID.UUID.String()
	}
	return d
}

func (h handlers) listPending(ctx context.Context, raw json.RawMessage) (any, error) {
	var args listPendingArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	params := approvalsvc.PendingParams{Params: args.Params, Kind: args.Kind, RunID: uniqueid.Optional(args.RunID), Status: args.Status, Reissue: args.ReissueLink}
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
		items = append(items, revertmcp.PendingRevert(*e.Revert))
	}
	return pagination.ToMCP(pagination.Page[any]{Items: items, NextCursor: page.NextCursor}), nil
}

// Tools are the tools that read held writes. mount lists a tool under its
// contract, around the agent's admission and error mapping; the tool list's
// composer supplies it.
type withdrawArgs struct {
	ApprovalID string `json:"approvalId" validate:"omitempty,uuid"`
	RevertID   string `json:"revertId" validate:"omitempty,uuid"`
	Reason     string `json:"reason" validate:"required,min=1,max=500"`
}

type withdrawResult struct {
	Kind          string                `json:"kind"`
	ApprovalID    string                `json:"approvalId,omitempty"`
	RevertID      string                `json:"revertId,omitempty"`
	Status        string                `json:"status"`
	WithdrawnAt   string                `json:"withdrawnAt,omitempty"`
	Reason        string                `json:"reason,omitempty"`
	Name          string                `json:"name,omitempty"`
	Instance      string                `json:"instance,omitempty"`
	PersonMessage string                `json:"personMessage"`
	NextSteps     []toolresult.NextStep `json:"nextSteps"`
}

func (h handlers) withdrawItem(ctx context.Context, raw json.RawMessage) (any, error) {
	var args withdrawArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if (args.ApprovalID == "") == (args.RevertID == "") {
		return nil, &guidance.ArgumentError{Message: "invalid arguments: name exactly one of approvalId (a held write or a plugin approval) " +
			"or revertId, with reason; nothing was withdrawn"}
	}
	p := approvalsvc.WithdrawParams{Reason: args.Reason}
	if args.ApprovalID != "" {
		p.ApprovalID = uuid.MustParse(args.ApprovalID)
	} else {
		p.RevertID = uuid.MustParse(args.RevertID)
	}
	w, err := h.withdraw.Withdraw(ctx, p)
	if err != nil {
		return nil, err
	}
	out := withdrawResult{
		Kind: w.Kind, Status: w.Status, Name: w.Name, Instance: w.Instance,
		PersonMessage: w.PersonMessage, NextSteps: w.NextSteps,
	}
	if w.Withdrawn() {
		out.Reason = w.Reason
		if w.WithdrawnAt != nil {
			out.WithdrawnAt = guidance.TimeText(*w.WithdrawnAt)
		}
	}
	if w.Kind == guidance.KindRevert {
		out.RevertID = w.ID.String()
	} else {
		out.ApprovalID = w.ID.String()
	}
	return out, nil
}

func Tools(svc Pending, withdraw Withdrawer, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc, withdraw: withdraw}
	return []mcpserver.Tool{
		mount("list_pending", h.listPending),
		mount("withdraw", h.withdrawItem),
	}
}
