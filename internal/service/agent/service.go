package agent

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

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
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// History is one page of a run's change records with the rows each wrote.
type History = action.History[action.Change, action.RowChange]

// Deps are a Service's dependencies, grouped by use case so each use case
// reads only its own group and can be lifted out with it. Core is shared by
// all of them. A port documented as optional may be nil; every other port
// is required and NewService refuses a Deps without it.
type Deps struct {
	Core     CoreDeps
	Write    WriteDeps
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

// WriteDeps is what the query and write tools use.
type WriteDeps struct {
	// Store checks a statement against the policy and runs it, through the
	// guard for a write.
	Store WriteStore
	// RLS says whether row-level security hides a table from the agent
	// (the RLS_HIDES_ROWS warning); optional, nothing is hidden when nil.
	RLS RLSChecker
	// PII sees every read's rows before they are returned and adds the
	// values of IDENTIFIER columns to the dictionary (M5.1); optional,
	// nothing is added when nil.
	PII PIIObserver
	// Record is the wire record of one change and its rows, as the ledger
	// renders it (run_history).
	Record func(ch action.Change, rows []action.RowChange) any
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
	Requests PluginRequests
	// ApprovalsVersion is the basalt_meta version that holds plugin
	// approvals.
	ApprovalsVersion int
}

// PIIObserver adds the PII values of rows the agent is about to get to the
// engine's dictionary. An error means a value could not be added: the rows
// are not returned (fail closed). It never logs a value.
type PIIObserver interface {
	Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error
}

type noPII struct{}

func (noPII) Observe(context.Context, []action.Column, []map[string]any) error { return nil }

// Service runs one agent's tool calls.
type Service struct {
	deps Deps
	// describe is the describe use case.
	describe *agentsvc.Service
	// delivery is how held actions reach the person.
	delivery *linksvc.Service
	// approval is the held writes use case.
	approval *approvalsvc.Service
	// revert is the revert use case.
	revert *revertsvc.Service
	// write is the query and write use case.
	write *writeCase
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
	if d.Write.RLS == nil {
		d.Write.RLS = noRLS{}
	}
	if d.Delivery.Relay == nil {
		d.Delivery.Relay = linksvc.NoRelay{NotConnected: d.Delivery.ErrVaultNotConnected}
	}
	if d.Write.PII == nil {
		d.Write.PII = noPII{}
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
	s.describe = agentsvc.New(s.agentCore(), &s.deps.Describe, s.status.UpdateInfo)
	// approval and delivery read each other: approval is built first and is
	// given the delivery and revert use cases once they exist.
	s.approval = approvalsvc.New(s.approvalCore(), &s.deps.Approval, liveWrites{&s.deps.Write}, runChecker{s.deps.Core.Store}, s)
	s.delivery = linksvc.New(s.linksCore(), &s.deps.Delivery, s.approval, s.Failure)
	s.revert = revertsvc.New(s.revertCore(), &s.deps.Revert, s.deps.Core.Store, s.delivery, s.describe, s)
	s.approval.SetDelivery(s.delivery)
	s.approval.SetReverts(s.revert)
	s.plugin = newPluginCase(&s.deps.Core, &s.deps.Plugin, s.delivery, s.status, s)
	s.ledger = ledgersvc.NewReads(s.deps.Core.Store)
	s.write = newWriteCase(&s.deps.Core, &s.deps.Write, s.delivery, s.approval, s.status, s)
}

// agentCore is the part of the shared settings the agent use cases read.
func (s *Service) agentCore() agentsvc.Core {
	c := s.deps.Core
	return agentsvc.Core{Store: c.Store, Commands: c.Commands, Errors: c.Errors}
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

// RunInfo is a started run.
type RunInfo struct {
	RunID     uuid.UUID
	TaskID    uuid.UUID
	Intent    string
	StartedAt time.Time
	// Warnings are what the person should hear about the setup, with the
	// steps for it (GUARD_UPGRADE_AVAILABLE).
	Warnings []toolresult.Warning
}

// StartRun starts a run with intent. taskID joins a task another agent
// started; uuid.Nil starts a new task.
func (wc *writeCase) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	run, err := wc.startRun(ctx, intent, taskID)
	if err != nil {
		return RunInfo{}, err
	}
	run.Warnings = wc.upgrade.UpgradeWarnings(ctx)
	return run, nil
}

// startRun is StartRun without the setup warnings, for the run a write
// starts for itself.
func (wc *writeCase) startRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	if taskID == uuid.Nil {
		taskID = newID()
	}
	run := RunInfo{RunID: newID(), TaskID: taskID, Intent: intent, StartedAt: wc.core.Now().UTC()}
	if err := wc.core.Store.StartRun(ctx, action.Intent{RunID: run.RunID, TaskID: taskID, Text: intent}); err != nil {
		return RunInfo{}, err
	}
	return run, nil
}

// QueryParams are one query call's validated arguments.
type QueryParams struct {
	SQL    string
	Params []any
	RunID  uuid.UUID // uuid.Nil when the read is outside a run
}

// QueryOutcome is one recorded read.
type QueryOutcome struct {
	action.ReadResult
	ChangeID uuid.UUID
	Warnings []toolresult.Warning
}

// Query checks sql against the policy, runs it read-only within the limits
// and records the read with the version of each row it could identify. A
// refused or failed statement is recorded as a REFUSED change. A read that
// cannot be recorded is not returned: the ledger must know what the agent
// saw.
func (wc *writeCase) Query(ctx context.Context, p QueryParams) (QueryOutcome, error) {
	run, err := ledgersvc.FindRun(ctx, wc.core.Store, p.RunID)
	if err != nil {
		return QueryOutcome{}, err
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: run.Intent}
	start := wc.core.Now()
	stmt, err := wc.deps.Store.Check(p.SQL, action.ToolQuery)
	if err == nil {
		err = checkArgs(stmt, p.Params)
	}
	if err != nil {
		return QueryOutcome{}, wc.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	res, err := wc.deps.Store.Read(ctx, p.SQL, p.Params, stmt)
	if err != nil {
		return QueryOutcome{}, wc.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	// The values of IDENTIFIER columns go in the dictionary before the rows
	// leave the engine (M5.1 plan, section 6). One that cannot be added
	// keeps the rows from the agent.
	if err := wc.deps.PII.Observe(ctx, res.Columns, res.Rows); err != nil {
		wc.core.Log.Error("pii: the read's values could not be added to the dictionary; its rows are withheld", "err", err)
		// An engine failure, not the agent's SQL: INTERNAL even when a
		// Postgres error (a map reload) caused it. The cause is logged above.
		return QueryOutcome{}, &toolresult.ToolError{Code: guidance.CodeInternal, Message: "internal engine error"}
	}
	change, err := wc.core.Store.RecordRead(ctx, action.Read{
		RunID: run.ID, Statement: p.SQL, Params: p.Params, Tables: stmt.Tables,
		Rows: len(res.Rows), Duration: res.Duration, Versions: res.Versions,
	})
	if err != nil {
		return QueryOutcome{}, fmt.Errorf("record read: %w", err)
	}
	return QueryOutcome{ReadResult: res, ChangeID: change, Warnings: wc.rlsWarnings(ctx, stmt.Tables, len(res.Rows))}, nil
}

// ListRuns returns one page of the agent's own runs with what each did.
func (wc *writeCase) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return wc.core.Store.ListRuns(ctx, p)
}

// recorded reports whether a failure is an action the ledger keeps as
// REFUSED: anything the policy, the guard or the database refused. Bad
// arguments, a missing run, and an unreachable database are not actions.
func recorded(code string) bool {
	switch code {
	case guidance.CodeInvalidArgument, guidance.CodeNotFound, guidance.CodeUnavailable, guidance.CodeInternal:
		return false
	}
	return true
}

// refused records a REFUSED change for err when it is an action the ledger
// keeps, and returns err. A failure to record is logged; the agent still
// gets the original refusal.
func (wc *writeCase) refused(ctx context.Context, in action.Intent, op action.Op, sql string, params []any, start time.Time, err error) error {
	te := guidance.MessageTooLarge(actionTool(op), err, wc.core.Errors.ToolError(err))
	if !recorded(te.Code) {
		return err
	}
	r := action.Refusal{
		Intent: in, Op: refusalOp(op), Statement: sql, Params: params,
		Code: te.Code, Reason: truncate(te.Message, maxReasonBytes), Duration: wc.core.Now().Sub(start),
	}
	if recErr := wc.core.Store.RecordRefusal(context.WithoutCancel(ctx), r); recErr != nil {
		wc.core.Log.Error("record refusal", "code", te.Code, "err", recErr)
	}
	return err
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func newID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}
