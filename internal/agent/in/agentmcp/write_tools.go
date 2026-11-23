package agentmcp

import (
	"context"
	"encoding/json"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// statusApplied is the status of an applied write.
const statusApplied = "APPLIED"

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

func writeResultFromDomain(o agentsvc.WriteOutcome) writeResult {
	out := writeResult{
		ChangeID: o.ChangeID.String(), RunID: o.RunID.String(), Op: string(o.Op), Rows: o.Rows,
		DurationMs: o.Duration.Milliseconds(), Status: statusApplied, Returning: o.Returning, Warnings: o.Warnings,
	}
	if o.Receipt != nil {
		out.PersonMessage, out.Receipt, out.NoReceipt = o.Receipt.Line, o.Receipt.Token, o.Receipt.Missing
	}
	return out
}

func (h handlers) write(ctx context.Context, raw json.RawMessage) (any, error) {
	var args writeArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		// An empty or missing intent is the contract's INTENT_REQUIRED.
		if intentMissing(raw) {
			return nil, &toolresult.ToolError{Code: guidance.CodeIntentRequired, Message: "write needs an intent: why this change is made"}
		}
		return nil, err
	}
	params, err := paramValues(args.Params)
	if err != nil {
		return nil, &guidance.ArgumentError{Message: err.Error()}
	}
	out, err := h.svc.Write(ctx, agentsvc.WriteParams{
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
	return guidance.DefaultApprovalWait
}

// WriteTools are the tools of a store that speaks SQL: query and write;
// none for another store (CONTRACT.md, Stores).
func WriteTools(svc Agent, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	if !speaksSQL(svc.StoreKind()) {
		return nil
	}
	h := handlers{svc: svc}
	return []mcpserver.Tool{
		mount("query", h.query),
		mount("write", h.write),
	}
}
