// Package ledgermcp serves the ledger's tools over MCP: run_history, the
// change records of one run. Handlers parse, validate, make one call to the
// ledger and render.
package ledgermcp

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Runs is the ledger's read side as run_history calls it, and the wire
// record of one change and its rows, as the ledger renders it.
type Runs interface {
	History(ctx context.Context, p action.ChangeListParams) (ledger.History, error)
	Record(ch action.Change, rows []action.RowChange) any
}

type handlers struct {
	svc Runs
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
		items = append(items, h.svc.Record(ch, hist.Rows[ch.ID]))
	}
	return pagination.ToMCP(pagination.Page[any]{Items: items, NextCursor: hist.Page.NextCursor}), nil
}

// Tools are the tools that read a run's history. mount lists a tool under
// its contract, around the agent's admission and error mapping; the tool
// list's composer supplies it.
func Tools(svc Runs, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool) []guidance.Tool {
	h := handlers{svc: svc}
	return []guidance.Tool{
		mount("run_history", h.runHistory),
	}
}
