package app

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

// changeHistory is one page of a run's change records with the rows each
// wrote.
type changeHistory = action.History[action.Change, action.RowChange]

// Deps are a Service's dependencies, grouped by use case so each use case
// reads only its own group and can be lifted out with it. Core is shared by
// all of them. A port documented as optional may be nil; every other port
// is required and NewService refuses a Deps without it.
type Deps struct {
	Core     coreDeps
	Agent    agentDeps
	Approval approvalDeps
	Revert   revertDeps
	Delivery linksvc.Deps
	Status   statussvc.Deps
	Plugin   pluginsvc.Deps
}

// coreDeps is what every use case shares: who the agent is, the ledger kept
// next to its store, the log and clock, the commands the person runs, how
// errors map to the contract, and where the pages are.
type coreDeps struct {
	Name string
	// Store is the agent's store, as far as every use case needs it: its
	// kind, what it can do, and its runs.
	Store agentStore
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
	plugin *pluginsvc.Service
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
		d.Core.Commands, _ = newCommands(d.Core.Name, "", "", d.Core.ServiceManager)
	}
	d.Core.Commands = d.Core.Commands.OperatedBy(d.Status.OperatedBy)
	if d.Core.LinkBudget <= 0 {
		d.Core.LinkBudget = links.DefaultBudget
	}
	if d.Delivery.Poll <= 0 {
		d.Delivery.Poll = defaultPoll
	}
	s := &Service{deps: d}
	s.wire()
	return s
}

// wire builds the use cases over the service's dependencies. Each holds a
// reference to its own group of s.deps and to the shared core group, and
// takes the other use cases it asks in its constructor: delivery reads the
// approval records from the store, so it comes first, then revert, approval
// and the agent.
func (s *Service) wire() {
	s.status = statussvc.New(s.statusCore(), &s.deps.Status)
	s.delivery = linksvc.New(s.linksCore(), &s.deps.Delivery, s.approvalReads(), s.Failure)
	s.revert = revertsvc.New(s.heldCore(), s.revertStoreSet(), &s.deps.Revert.Deps, s.deps.Core.Store, s.delivery, storeStatementLimit(s.deps.Agent), s)
	s.approval = approvalsvc.New(s.heldCore(), s.approvalStoreSet(), &s.deps.Approval.Deps, s.delivery, s.revert, runChecker{s.deps.Core.Store}, s)
	s.agent = agentsvc.New(s.agentCore(), s.agentStoreSet(), s.deps.Agent.PII, s.status.UpdateInfo, s.delivery, s.approval, s.status, s, s)
	s.plugin = pluginsvc.New(s.pluginCore(), &s.deps.Plugin, s.delivery, s.status, s)
	s.ledger = ledgersvc.NewReads(s.deps.Core.Store)
}

// approvalReads is what the delivery use case reads of the approval
// records: the approval's store and its column order.
func (s *Service) approvalReads() approvalReads {
	return approvalReads{records: s.approvalStoreSet().Records, columns: s.deps.Approval.Columns}
}

// storeStatementLimit is the agent's statement timeout, which a revert's
// answer names: the store's limits, or 0 for an agent served without store
// data.
func storeStatementLimit(a agentDeps) statementLimit {
	if a.Data == nil {
		return 0
	}
	return statementLimit(a.Limits.StatementTimeout)
}

// statementLimit answers the revert use case's read of the agent's statement
// timeout.
type statementLimit time.Duration

func (l statementLimit) StatementTimeout() time.Duration { return time.Duration(l) }

// agentCore is the part of the shared settings the agent use cases read.
func (s *Service) agentCore() agentsvc.Core {
	c := s.deps.Core
	return agentsvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors}
}

// statusCore is the part of the shared settings the status use case reads.
func (s *Service) statusCore() statussvc.Core {
	c := s.deps.Core
	return statussvc.Core{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, PagesOrigin: c.PagesOrigin, LinkBudget: c.LinkBudget}
}

// pluginCore is the part of the shared settings the plugin use case reads.
func (s *Service) pluginCore() pluginsvc.Core {
	c := s.deps.Core
	return pluginsvc.Core{Name: c.Name, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesOrigin: c.PagesOrigin}
}

// heldCore is the part of the shared settings the approval and revert use
// cases read.
func (s *Service) heldCore() guidance.HeldCore {
	c := s.deps.Core
	return guidance.HeldCore{Name: c.Name, Log: c.Log, Now: c.Now, Commands: c.Commands, Errors: c.Errors, PagesBase: c.PagesBase, LinkBudget: c.LinkBudget}
}

// runChecker answers whether a run is one of the agent's, from its ledger.
type runChecker struct{ store agentStore }

func (r runChecker) CheckRun(ctx context.Context, id uuid.UUID) error {
	return ledgersvc.CheckRun(ctx, r.store, id)
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
	need("Agent.Data", d.Agent.Data == nil)
	need("Agent.Record", d.Agent.Record == nil)
	need("Approval.Store", d.Approval.Store == nil)
	// The approval service relays the person's signed approval to the store,
	// which must check the signature itself until the engine has a verifier
	// of its own.
	need("Approval.SignatureCheck", d.Core.Store != nil && !d.Core.Store.Capabilities().InStoreSignatureCheck)
	need("Revert.Store", d.Revert.Store == nil)
	// The revert service hands the person's proofs to the store, which must
	// check the signature itself until the engine has a verifier of its own.
	need("Revert.SignatureCheck", d.Core.Store != nil && !d.Core.Store.Capabilities().InStoreSignatureCheck)
	need("Revert.AfterAnswer", d.Revert.AfterAnswer == nil)
	need("Revert.RotateSession", d.Revert.RotateSession == nil)
	need("Delivery.VaultConflict", d.Delivery.VaultConflict == nil)
	need("Delivery.ErrVaultNotConnected", d.Delivery.ErrVaultNotConnected == nil)
	need("Status.Passkeys", d.Status.Passkeys == nil)
	need("Status.CrashReports", d.Status.CrashReports == nil)
	need("Status.CrashFile", d.Status.CrashFile == nil)
	need("Status.LatestGuardVersion", d.Status.LatestGuardVersion == nil)
	need("Status.UpdateMessage", d.Status.UpdateMessage == nil)
	need("Status.StartHoldOffUntil", d.Status.StartHoldOffUntil == nil)
	return out
}
