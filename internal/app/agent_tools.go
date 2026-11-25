package app

import (
	"context"
	"encoding/json"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/agent/in/agentmcp"
	"github.com/basaltdbhq/basaltdb/internal/approval/in/approvalmcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/handoff/in/handoffmcp"
	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/ledger/in/ledgermcp"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	pluginsvc "github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/in/pluginmcp"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"
	"github.com/basaltdbhq/basaltdb/internal/status/in/statusmcp"
)

// AgentTools are the tools of svc as the MCP server serves them: every
// contract in api/mcp that is IMPLEMENTED, each listed with the contract's
// description and input schema, and query and write only for a store of
// the SQL family (CONTRACT.md, Stores). Each tool's call goes through
// agentmcp.Wrap; the lists join in the served order.
func AgentTools(svc *Service) []mcpserver.Tool {
	if svc == nil {
		panic("agent: service required")
	}
	mount := func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
		return contractTool(name, agentmcp.Wrap(svc, name, call))
	}
	agent := svc.agent
	tools := agentmcp.RunStartTools(agent, mount)
	for _, list := range [][]mcpserver.Tool{
		agentmcp.WriteTools(agent, mount), ledgermcp.Tools(ledgerRuns{Reads: svc.ledger, agent: &svc.deps.Agent}, mount), agentmcp.RunTools(agent, mount),
		approvalmcp.Tools(svc.approval, mount), revertmcp.Tools(svc.revert, mount), pluginmcp.Tools(pluginRequester{svc.plugin}, mount),
		agentmcp.DescribeTools(agent, mount), statusmcp.Tools(svc.status, mount), handoffmcp.Tools(mount),
	} {
		tools = append(tools, list...)
	}
	return tools
}

// ledgerRuns is the ledger's read side as run_history calls it, with the
// wire record the ledger renders.
type ledgerRuns struct {
	*ledgersvc.Reads
	agent *agentDeps
}

// Record is the wire record of one change and its rows, as the ledger
// renders it (run_history).
func (l ledgerRuns) Record(ch action.Change, rows []action.RowChange) any {
	return l.agent.Record(ch, rows)
}

// pluginRequester is the plugin use case as request_plugin calls it.
type pluginRequester struct{ plugin *pluginsvc.Service }

// RequestPlugin serves request_plugin: it prepares a plugin install or
// change for the person to approve, waits once for it, or removes a plugin.
// meta is the request's _meta object, nil when it had none.
func (p pluginRequester) RequestPlugin(ctx context.Context, source, name, instance string, agents []string, remove *bool, approvalID string, waitForApproval *int, meta json.RawMessage) (any, error) {
	return p.plugin.RequestPlugin(ctx, source, name, instance, agents, remove, approvalID, waitForApproval, meta)
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
