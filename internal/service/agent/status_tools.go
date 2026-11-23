package agent

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

func (h handlers) status(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return h.svc.Status(ctx)
}

// statusTools are the tools that report the agent's state and confirm the
// collected database.
func (h handlers) statusTools() []guidance.Tool {
	return []guidance.Tool{
		contractTool(guidance.ToolStatus, h.wrap(guidance.ToolStatus, h.status)),
		contractTool(guidance.ToolConfirmDatabase, h.wrap(guidance.ToolConfirmDatabase, h.confirmDatabase)),
	}
}
