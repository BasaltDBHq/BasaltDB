package agent

import (
	"context"
	"crypto/rand"
	"log/slog"
	"strings"
	"time"

	pluginsvc "github.com/basaltdbhq/basaltdb/internal/plugin"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
	statussvc "github.com/basaltdbhq/basaltdb/internal/status"

	ledgersvc "github.com/basaltdbhq/basaltdb/internal/ledger"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// History is one page of a run's change records with the rows each wrote.
type History = action.History[action.Change, action.RowChange]

// Deps are a Service's dependencies, grouped by use case so each use case
// reads only its own group and can be lifted out with it. Core is shared by
// all of them. A port documented as optional may be nil; every other port
// is required and NewService refuses a Deps without it.
type Deps struct {
	Core     CoreDeps
	Write    agentsvc.WriteDeps
	Approval approvalsvc.Deps
	Revert   revertsvc.Deps
	Delivery linksvc.Deps
	Status   statussvc.Deps
	Describe agentsvc.DescribeDeps
	Plugin   PluginDeps
}

// CoreDeps is what every use case shares: who the agent is, the ledger kept
// next to its store, the log and clock, the commands the person runs, how
// errors map to the contract, and where the pages are.
type CoreDeps struct {
	Name string
	// Store is the agent's store, as far as every use case needs it: its
	// kind, what it can do, and its runs.
	Store Store
	Log   *slog.Logger
	Now   func() time.Time
	// Commands builds the commands the person runs for this agent; the
	// default ones for Name and the platform's default config when zero.
	Commands guidance.Commands
	// ServiceManager is the host's service manager, for the default
	// Commands.
	ServiceManager guidance.ServiceManager
	// Errors tells apart the error values of the adapters.
	Errors guidance.ErrorMap
	// PagesBase is the base URL of the approval and revert pages (links);
	// links.DefaultLocal when empty.
	PagesBase string
	// PagesOrigin is the origin of the pages the engine serves itself
	// (CONTRACT.md, Local pages), for short links; empty when it serves
	// none, and held actions then carry the long link.
	PagesOrigin string
	// LinkBudget is the longest long link, in characters of the whole URL,
	// handed to an agent as the way to open a page (CONTRACT.md, The link
	// budget); links.DefaultBudget when zero.
	LinkBudget int
}

// PluginDeps is what the plugin tools and the plugin approval pages use.
type PluginDeps struct {
	// Approvals are the guard's plugin approvals on the agent's credential,
	// for the plugin approval routes of the pages; optional, and those
	// routes know no plugin approval of this agent when nil.
	Approvals PluginApprovalStore
	// Requests serve request_plugin with the engine-kept plugin entries of
	// a service engine; nil on any other engine, where the tool is refused
	// (CONTRACT.md, MCP tools, request_plugin).
	Requests pluginsvc.PluginRequests
	// ApprovalsVersion is the basalt_meta version that holds plugin
	// approvals.
	ApprovalsVersion int
}

// Service runs one agent's tool calls.
type Service struct {
	deps Deps
	// agent is the describe, run, query and write use case.
	agent *agentsvc.Service
	// delivery is how held actions reach the person.
	delivery *linksvc.Service
	// approval is the held writes use case.
	approval *approvalsvc.Service
	// revert is the revert use case.
	revert *revertsvc.Service
	// ledger is the read side of the ledger: run history.
	ledger *ledgersvc.Reads
	// plugin is the plugin use case.
	plugin *pluginCase
	// status is the status use case.
	status *statussvc.Service
}

// NewService returns the service for one agent. It panics on a missing
// required port, naming it.
func NewService(d Deps) *Service {
	if missing := d.missing(); len(missing) > 0 {
		panic("agent: required dependencies missing: " + strings.Join(missing, ", "))
	}
	if d.Delivery.Notifier == nil {
		d.Delivery.Notifier = linksvc.NoNotifier{}
	}
	if d.Delivery.Relay == nil {
		d.Delivery.Relay = linksvc.NoRelay{NotConnected: d.Delivery.ErrVaultNotConnected}
	}
	if d.Core.PagesBase == "" {
		d.Core.PagesBase = links.DefaultLocal
	}
	if d.Delivery.Links == nil {
		d.Delivery.Links = links.NewSecrets(time.Now, rand.Reader)
	}
	if d.Core.Commands.AgentName() == "" {
		// A name and no config path cannot fail.
		d.Core.Commands, _ = NewCommands(d.Core.Name, "", "", d.Core.ServiceManager)
	}
	d.Core.Commands = d.Core.Commands.OperatedBy(d.Status.OperatedBy)
	if d.Core.LinkBudget <= 0 {
		d.Core.LinkBudget = links.DefaultBudget
	}
	if d.Delivery.Poll <= 0 {
		d.Delivery.Poll = DefaultPoll
	}
	s := &Service{deps: d}
	s.wire()
	return s
}

// wire builds the use cases over the service's dependencies. Each holds a
// reference to its own group of s.deps and to the shared core group.
func (s *Service) wire() {
	s.status = statussvc.NewService(s.statusCore(), &s.deps.Status)
	s.agent = agentsvc.New(s.agentCore(), &s.deps.Describe, &s.deps.Write, s.status.UpdateInfo)
	// approval and delivery read each other: approval is built first and is
	// given the delivery and revert use cases once they exist.
	s.approval = approvalsvc.New(s.approvalCore(), &s.deps.Approval, liveWrites{&s.deps.Write}, runChecker{s.deps.Core.Store}, s)
	s.delivery = linksvc.New(s.linksCore(), &s.deps.Delivery, s.approval, s.Failure)
	s.revert = revertsvc.New(s.revertCore(), &s.deps.Revert, s.deps.Core.Store, s.delivery, s.agent, s)
	s.approval.SetDelivery(s.delivery)
	s.approval.SetReverts(s.revert)
	s.plugin = newPluginCase(&s.deps.Core, &s.deps.Plugin, s.delivery, s.status, s)
	s.ledger = ledgersvc.NewReads(s.deps.Core.Store)
	s.agent.SetPorts(s.delivery, s.approval, s.status, s, s)
}

// agentCore is the part of the shared settings the agent use cases read.
func (s *Service) agentCore() agentsvc.Core {
	c := s.deps.Core
	return agentsvc.Core{Name: c.Name, Store: c.Store, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors}
}

// statusCore is the part of the shared settings the status use case reads.
func (s *Service) statusCore() statussvc.Core {
	c := s.deps.Core
	return statussvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, PagesOrigin: c.PagesOrigin, LinkBudget: c.LinkBudget}
}

// revertCore is the part of the shared settings the revert use case reads.
func (s *Service) revertCore() revertsvc.Core {
	c := s.deps.Core
	return revertsvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, LinkBudget: c.LinkBudget}
}

// approvalCore is the part of the shared settings the approval use case reads.
func (s *Service) approvalCore() approvalsvc.Core {
	c := s.deps.Core
	return approvalsvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, LinkBudget: c.LinkBudget}
}

// runChecker answers whether a run is one of the agent's, from its ledger.
type runChecker struct{ store Store }

func (r runChecker) CheckRun(ctx context.Context, id uuid.UUID) error {
	_, err := ledgersvc.FindRun(ctx, r.store, id)
	return err
}

// linksCore is the part of the shared settings the delivery use case reads.
func (s *Service) linksCore() linksvc.Core {
	c := s.deps.Core
	return linksvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, PagesOrigin: c.PagesOrigin}
}

// missing names the required ports d lacks.
func (d Deps) missing() []string {
	var out []string
	need := func(name string, nilPort bool) {
		if nilPort {
			out = append(out, name)
		}
	}
	need("Core.Name", d.Core.Name == "")
	need("Core.Store", d.Core.Store == nil)
	need("Core.Log", d.Core.Log == nil)
	need("Core.Now", d.Core.Now == nil)
	need("Core.Errors.InvalidParams", d.Core.Errors.InvalidParams == nil)
	need("Core.Errors.InvalidIntent", d.Core.Errors.InvalidIntent == nil)
	need("Core.Errors.RowTooLarge", d.Core.Errors.RowTooLarge == nil)
	need("Core.ServiceManager", d.Core.ServiceManager.StartCommand == nil || d.Core.ServiceManager.RestartArgs == nil)
	need("Write.Store", d.Write.Store == nil)
	need("Write.Record", d.Write.Record == nil)
	need("Approval.Store", d.Approval.Store == nil)
	need("Approval.ErrNotFound", d.Approval.ErrNotFound == nil)
	need("Revert.Store", d.Revert.Store == nil)
	need("Revert.ErrNotFound", d.Revert.ErrNotFound == nil)
	need("Revert.AfterAnswer", d.Revert.AfterAnswer == nil)
	need("Revert.RotateSession", d.Revert.RotateSession == nil)
	need("Delivery.VaultConflict", d.Delivery.VaultConflict == nil)
	need("Delivery.ErrVaultNotConnected", d.Delivery.ErrVaultNotConnected == nil)
	need("Status.Passkeys", d.Status.Passkeys == nil)
	need("Status.CrashReports", d.Status.CrashReports == nil)
	need("Status.LatestGuardVersion", d.Status.LatestGuardVersion == nil)
	need("Status.UpdateMessage", d.Status.UpdateMessage == nil)
	need("Status.StartHoldOffUntil", d.Status.StartHoldOffUntil == nil)
	return out
}
