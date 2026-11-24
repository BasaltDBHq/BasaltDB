// Package pluginmcp serves the plugin tools over MCP: request_plugin.
// Handlers parse, validate, make one call to the plugin use case and render.
package pluginmcp

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// Plugins is the plugin use case as request_plugin calls it: meta is the
// request's _meta object (the files basalt mcp uploaded), nil when it had
// none.
type Plugins interface {
	RequestPlugin(ctx context.Context, source, name, instance string, agents []string, remove *bool, approvalID string, waitForApproval *int, meta json.RawMessage) (any, error)
}

type handlers struct {
	svc Plugins
}

// request_plugin (CONTRACT.md, MCP tools, request_plugin): the agent
// prepares a plugin install or change that the person approves on the
// plugin approval page, waits once for it, or removes a plugin. The agent
// never approves: nothing here signs, relays or holds a plugin signature.

const toolRequestPlugin = guidance.ToolRequestPlugin

// requestPluginArgs is the request_plugin tool's input
// (api/mcp/tools/request_plugin.json).
type requestPluginArgs struct {
	Source          string   `json:"source" validate:"omitempty,min=2,max=4096,startswith=/"`
	Name            string   `json:"name" validate:"omitempty,max=40"`
	Instance        string   `json:"instance" validate:"omitempty,max=32"`
	Agents          []string `json:"agents" validate:"omitempty,min=1,max=256,unique,dive,max=63"`
	Remove          *bool    `json:"remove"`
	ApprovalID      string   `json:"approvalId" validate:"omitempty,uuid"`
	WaitForApproval *int     `json:"waitForApproval" validate:"omitempty,min=0,max=110"`
}

func (h handlers) requestPlugin(ctx context.Context, raw json.RawMessage) (any, error) {
	var args requestPluginArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if err := args.check(); err != nil {
		return nil, err
	}
	return h.svc.RequestPlugin(ctx, args.Source, args.Name, args.Instance, args.Agents, args.Remove, args.ApprovalID, args.WaitForApproval, mcpserver.Meta(ctx))
}

// check holds the call to exactly one form.
func (a requestPluginArgs) check() error {
	forms := 0
	for _, given := range []bool{a.Source != "", a.Name != "", a.ApprovalID != ""} {
		if given {
			forms++
		}
	}
	remove := a.Remove != nil && *a.Remove
	switch {
	case forms != 1:
		return &guidance.ArgumentError{Message: "name exactly one of source, name or approvalId"}
	case a.ApprovalID != "" && (a.Instance != "" || a.Agents != nil || a.Remove != nil):
		return &guidance.ArgumentError{Message: "approvalId takes nothing but waitForApproval"}
	case a.ApprovalID == "" && a.WaitForApproval != nil:
		return &guidance.ArgumentError{Message: "waitForApproval is only for approvalId"}
	case a.Remove != nil && a.Name == "":
		return &guidance.ArgumentError{Message: "remove is only for name"}
	case remove && a.Agents != nil:
		return &guidance.ArgumentError{Message: "remove takes no agents: the plugin stops for every agent it served"}
	}
	return nil
}

// Tools are the tools that ask for a plugin. mount lists a tool under its
// contract, around the agent's admission and error mapping; the tool list's
// composer supplies it.
func Tools(svc Plugins, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc}
	return []mcpserver.Tool{
		mount(toolRequestPlugin, h.requestPlugin),
	}
}
