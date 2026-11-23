package statusmcp

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// Reporter is the status use case as the served agent's status tool calls
// it.
type Reporter interface {
	Status(ctx context.Context) (guidance.StatusReport, error)
}

type handlers struct {
	svc Reporter
}

func (h handlers) status(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return h.svc.Status(ctx)
}

// Tools are the tools that report the agent's state. mount lists a tool
// under its contract, around the agent's admission and error mapping; the
// tool list's composer supplies it.
func Tools(svc Reporter, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc}
	return []mcpserver.Tool{
		mount(guidance.ToolStatus, h.status),
	}
}
