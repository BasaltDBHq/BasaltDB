// Package handoffmcp serves the hand-off's tools over MCP: confirm_database
// on a served agent, where no connect-only database waits.
package handoffmcp

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// --- the served agent's confirm_database ---

// confirmDatabase answers confirm_database on an agent with no connect-only
// setup waiting: INVALID_ARGUMENT.
func confirmDatabase(_ context.Context, raw json.RawMessage) (any, error) {
	var args handoff.ConfirmArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return nil, &guidance.ArgumentError{Message: handoff.ErrNotWaiting.Error()}
}

// Tools are the tools that confirm the collected database, on an agent
// with no connect-only setup waiting. mount lists a tool under its contract,
// around the agent's admission and error mapping; the tool list's composer
// supplies it.
func Tools(mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	return []mcpserver.Tool{
		mount(guidance.ToolConfirmDatabase, confirmDatabase),
	}
}
