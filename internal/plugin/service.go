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

// Service is the plugin use case: request_plugin and the plugin approval
// pages. It holds its own copy of the core settings and a reference to its
// own Deps. What it needs from the delivery and status use cases it names as
// small ports of its own.
type Service struct {
	core     Core
	deps     *Deps
	delivery Delivery
	status   StatusView
	admit    Admitter
}

// New builds the plugin use case over core and deps.
func New(core Core, deps *Deps, delivery Delivery, status StatusView, admit Admitter) *Service {
	return &Service{core: core, deps: deps, delivery: delivery, status: status, admit: admit}
}
