package plugin

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Core is the part of the shared settings the plugin use case reads.
type Core struct {
	Name        string
	Now         func() time.Time
	Commands    guidance.Commands
	Errors      guidance.ErrorMap
	PagesOrigin string
}

// Deps is what the plugin tools and the plugin approval pages use.
type Deps struct {
	// Approvals are the guard's plugin approvals on the agent's credential,
	// for the plugin approval routes of the pages; optional, and those
	// routes know no plugin approval of this agent when nil.
	Approvals PluginApprovalStore
	// Requests serve request_plugin with the engine-kept plugin entries of
	// a service engine; nil on any other engine, where the tool is refused
	// (CONTRACT.md, MCP tools, request_plugin).
	Requests PluginRequests
	// ApprovalsVersion is the basalt_meta version that holds plugin
	// approvals.
	ApprovalsVersion int
}
