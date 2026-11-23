package app

import (
	"context"
	"encoding/json"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/agent/in/agentmcp"
	"github.com/basaltdbhq/basaltdb/internal/approval/in/approvalmcp"
	"github.com/basaltdbhq/basaltdb/internal/handoff/in/handoffmcp"
	"github.com/basaltdbhq/basaltdb/internal/ledger/in/ledgermcp"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/plugin/in/pluginmcp"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"
	"github.com/basaltdbhq/basaltdb/internal/status/in/statusmcp"
)

// AgentTools are the tools of svc as the MCP server serves them: every
// contract in api/mcp that is IMPLEMENTED, each listed with the contract's
// description and input schema, and query and write only for a store that
// speaks SQL (CONTRACT.md, Stores). Each tool's call goes through
// agentmcp.Wrap; the lists join in the served order.
func AgentTools(svc *Service) []mcpserver.Tool {
	if svc == nil {
		panic("agent: service required")
	}
	mount := func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
		return contractTool(name, agentmcp.Wrap(svc, name, call))
	}
	tools := agentmcp.RunStartTools(svc, mount)
	for _, list := range [][]mcpserver.Tool{
		agentmcp.WriteTools(svc, mount), ledgermcp.Tools(svc, mount), agentmcp.RunTools(svc, mount), approvalmcp.Tools(svc, mount), revertmcp.Tools(svc, mount),
		pluginmcp.Tools(svc, mount), agentmcp.DescribeTools(svc, mount), statusmcp.Tools(svc, mount), handoffmcp.Tools(mount),
	} {
		tools = append(tools, list...)
	}
	return tools
}

// connectOnlyGuide is the error presenter of the connect-only agent c: an
// agent service with only what the error guidance reads, built for each
// failure.
func connectOnlyGuide(c handoffmcp.ConnectOnly) handoffmcp.Failures {
	return newGuide(c.Name, c.Commands.OperatedBy(c.OperatedBy), c.Log, c.Now, c.Errors, c.ConnectBudget)
}

// contractTool builds a tool from its contract. A missing contract is a
// build defect: the contract test keeps served tools and contracts aligned.
func contractTool(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
	c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
	if !ok {
		panic("agent: no contract for tool " + name)
	}
	return mcpserver.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: call}
}
