package agent

import (
	"context"
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

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
	return h.svc.plugin.RequestPlugin(ctx, args.Source, args.Name, args.Instance, args.Agents, args.Remove, args.ApprovalID, args.WaitForApproval, metaOf(ctx))
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

// PluginTools are the tools that ask for a plugin.
func PluginTools(svc *Service, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool) []guidance.Tool {
	h := handlers{svc: svc}
	return []guidance.Tool{
		mount(toolRequestPlugin, h.requestPlugin),
	}
}
