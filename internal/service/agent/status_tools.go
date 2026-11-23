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

// StatusTools are the tools that report the agent's state and confirm the
// collected database.
func StatusTools(svc *Service, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool) []guidance.Tool {
	h := handlers{svc: svc}
	return []guidance.Tool{
		mount(guidance.ToolStatus, h.status),
		mount(guidance.ToolConfirmDatabase, h.confirmDatabase),
	}
}
