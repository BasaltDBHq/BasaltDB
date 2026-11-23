package mcpserver

import (
	"context"
	"encoding/json"
)

// ToolShape is the shape of a tool a service declares for itself: the same
// four fields as Tool, so a service's descriptor converts to a Tool without
// the service importing this package.
type ToolShape interface {
	~struct {
		Name        string
		Description string
		InputSchema map[string]any
		Call        func(ctx context.Context, args json.RawMessage) (any, error)
	}
}

// ToolsFrom converts a service's tool descriptors to Tools. withMeta is the
// service's way to carry the request's _meta object (Meta) to its handler:
// each call gets its context through it. It may be nil, for a service that
// reads no _meta.
func ToolsFrom[T ToolShape](tools []T, withMeta func(context.Context, json.RawMessage) context.Context) []Tool {
	out := make([]Tool, 0, len(tools))
	for _, d := range tools {
		t := Tool(d)
		if withMeta != nil {
			call := t.Call
			t.Call = func(ctx context.Context, args json.RawMessage) (any, error) {
				return call(withMeta(ctx, Meta(ctx)), args)
			}
		}
		out = append(out, t)
	}
	return out
}
