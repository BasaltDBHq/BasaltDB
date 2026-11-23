package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
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
	Approval ApprovalDeps
	Revert   RevertDeps
	Delivery DeliveryDeps
	Status   StatusDeps
	Describe DescribeDeps
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

// ApprovalDeps is what held writes use: the approvals in the store and the
// ledger's values the agent maps to tool errors.
type ApprovalDeps struct {
	Store Approvals
	// ErrNotFound is the ledger's answer for an approval the role does not
	// hold.
	ErrNotFound error
	// SortSpec whitelists the approval list sort.
	SortSpec pagination.SortSpec
	// Columns reads each table's columns in table order for the pages;
	// optional, and the pages show the order the rows carry when nil.
	Columns ColumnOrder
}

// RevertDeps is what reverts use.
type RevertDeps struct {
	Store Reverts
	// ErrNotFound is the ledger's answer for a revert the role did not
	// prepare.
	ErrNotFound error
	// AfterAnswer runs f after the answer of the Vault session ctx belongs
	// to (false: there is none). RotateSession moves that session onto
	// token.
	AfterAnswer   func(ctx context.Context, f func()) bool
	RotateSession func(ctx context.Context, token channel.LinkToken) bool
}

// DeliveryDeps is how a held write or a revert reaches the person: the
// notices, the short links and the receipts of what the person signed.
type DeliveryDeps struct {
	// Notifier is optional: no notification when nil.
	Notifier Notifier
	// Deliverer takes the notice of each answer that holds a write, prepares
	// a revert or issues a new link on the agent's request, for the
	// approval.deliver plugins; optional, none when nil.
	Deliverer LinkDeliverer
	// Links holds the short links' secrets, shared with the pages; a store
	// of its own when nil.
	Links *links.Secrets
	// Relay registers portal short links with the Vault; optional, none
	// when nil (the Vault is off).
	Relay LinkRelay
	// VaultConflict reports whether err is the Vault's answer that another
	// engine holds a link's token. ErrVaultNotConnected is what a relay
	// answers when no Vault is connected.
	VaultConflict        func(err error) bool
	ErrVaultNotConnected error
	// Poll is how often a waiting call reads whether the person signed;
	// DefaultPoll when zero.
	Poll time.Duration
	// Receipts is the engine's signing key, which signs the receipt of
	// every signature the engine relays (CONTRACT.md, Vault channel,
	// Receipts). Nil when the key file is refused (KEY_ERROR): answers then
	// carry noReceipt.
	Receipts ReceiptSigner
}

// StatusDeps is what the status tool reports beyond the database, all
// optional unless noted (CONTRACT.md, MCP tools, status).
type StatusDeps struct {
	// Passkeys lists the person's passkeys, to count them; required.
	Passkeys PasskeyLister
	// OperatedBy is engine.json operatedBy (PERSON when empty); SameUser is
	// an engine run as the person's own OS user (enforcement GUARD_ONLY);
	// Setup is the agent's pending setup code from the config; Build is the
	// engine's build (buildinfo.Version when empty).
	OperatedBy string
	SameUser   bool
	// DevLocalPages is engine.json devLocalPages: every personMessage starts
	// with the DEV_LOCAL_PAGES warning and status reports the problem
	// (CONTRACT.md, Page origins).
	DevLocalPages bool
	// ConnectBudget is the link budget for the connect link when the
	// engine hands one (config.ConnectLinkBudget), else 0: next steps for a
	// pending setup then put the link first (CONTRACT.md, Connect).
	ConnectBudget int
	Setup         *config.Setup
	Build         string
	// StartedBy is why this engine started: hand, mcp or crash (status
	// engine.startedBy); empty reports nothing.
	StartedBy string
	// Probe reads the guard's state and the agent's setups on its
	// credential, for status and to admit each call; a current guard when
	// nil.
	Probe Probe
	// Upgrade says whether only non-breaking guard migrations are missing
	// (the GUARD_UPGRADE_AVAILABLE warning); optional, Probe answers when nil.
	Upgrade UpgradeChecker
	// Vault reports the engine's Vault connection for status; status leaves
	// vault out when nil.
	Vault VaultReporter
	// Update gives the newer release the engine knows of, from its daily
	// check (CONTRACT.md, Update notice); optional, nil or a nil result
	// when none.
	Update func() *UpdateNotice
	// Portal reports the engine's last daily portal check for status
	// (problem PORTAL_MISMATCH); status says nothing about the portal when
	// nil.
	Portal PortalReporter
	// Plugins reports the engine's plugin entries listed for this agent
	// that do not serve it (problems PLUGIN_UNAVAILABLE and
	// PLUGIN_NOT_TRUSTED); status says nothing about plugins when nil.
	Plugins PluginReporter
	// CrashDirs are the directories crash reports are saved in, for
	// status.crash; Access lists the agent role's tables, for
	// status.access. Each is left out of status when nil or empty.
	CrashDirs []string
	Access    AccessReader
	// EngineRecord reads this engine's row in the agent's database for the
	// status tool's engineRecord; nil makes its state UNKNOWN.
	EngineRecord EngineRecordReader
	// Trust says what verifies the agent's database certificate now (status
	// trust, problems TRUST_ROOT_EXPIRING and TRUST_PROFILE_REFUSED); status
	// leaves trust out when nil.
	Trust TrustReporter
	// Database names the database the agent's credential connects to, as
	// status names a connect-only setup's database ("<host>:<port>, database
	// <db>"); empty when unknown.
	Database string
	// Finisher finishes a setup the database shows recorded: it promotes a
	// rotated credential and clears setup from engine.json. Optional: the
	// setup is then only forgotten in memory.
	Finisher SetupFinisher
	// The functions that read the host: all required.
	// CrashReports are the crash reports in dirs, newest first.
	CrashReports func(dirs ...string) []CrashReport
	// LatestGuardVersion is the basalt_meta version this build installs.
	LatestGuardVersion func() int
	// UpdateMessage is the notice for the agent to relay, for the binary
	// at exe.
	UpdateMessage func(n UpdateNotice, exe string) string
	// StartHoldOffUntil is when the supervisor tries the engine again after
	// it gave up (false when it holds nothing off).
	StartHoldOffUntil func(stop LastStop, configPath string, now time.Time) (time.Time, bool)
}

// DescribeDeps is what the describe tool reads.
type DescribeDeps struct {
	// Catalog reads the database's structure for describe; optional, and
	// describe answers INTERNAL when nil.
	Catalog Catalog
	// Classes are the agent's PII classes for describe; optional, and
	// describe fails closed (INTERNAL) when nil: it cannot tell a SECRET
	// column.
	Classes ClassResolver
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

// PasskeyLister lists the person's passkeys.
type PasskeyLister interface {
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
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
	// setupMu guards setup, the agent's pending setup: Status.Setup until
	// the database shows it recorded.
	setupMu sync.Mutex
	setup   *config.Setup
	// notRecorded is the held calls' cache of a setup not recorded yet.
	notRecorded setupCache
	// lockTrouble is a lock file the engine could not open while finishing
	// a setup (problem LOCK_FILE_UNUSABLE).
	lockTrouble lockTrouble
	// rescopes are the reverts the person rescoped through this engine,
	// in memory only (CONTRACT.md, Rescope, widen and reject).
	rescopes *rescopes
	// describe is the describe use case.
	describe *describeCase
	// delivery is how held actions reach the person.
	delivery *deliveryCase
	// approval is the held writes use case.
	approval *approvalCase
}

// NewService returns the service for one agent. It panics on a missing
// required port, naming it.
func NewService(d Deps) *Service {
	if missing := d.missing(); len(missing) > 0 {
		panic("agent: required dependencies missing: " + strings.Join(missing, ", "))
	}
	if d.Delivery.Notifier == nil {
		d.Delivery.Notifier = noNotifier{}
	}
	if d.Write.RLS == nil {
		d.Write.RLS = noRLS{}
	}
	if d.Status.Probe == nil {
		d.Status.Probe = noProbe{latest: d.Status.LatestGuardVersion}
	}
	if d.Status.Finisher == nil {
		d.Status.Finisher = noFinisher{}
	}
	if d.Status.Upgrade == nil {
		d.Status.Upgrade = guardUpgrade{probe: d.Status.Probe}
	}
	if d.Status.Build == "" {
		d.Status.Build = buildinfo.Version
	}
	if d.Delivery.Relay == nil {
		d.Delivery.Relay = noRelay{notConnected: d.Delivery.ErrVaultNotConnected}
	}
	if d.Write.PII == nil {
		d.Write.PII = noPII{}
	}
	if d.Describe.Catalog == nil {
		d.Describe.Catalog = noCatalog{}
	}
	if d.Describe.Classes == nil {
		d.Describe.Classes = noClasses{}
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
	s := &Service{deps: d, setup: d.Status.Setup, rescopes: newRescopes()}
	s.wire()
	return s
}

// wire builds the use cases over the service's dependencies. Each holds a
// reference to its own group of s.deps and to the shared core group.
func (s *Service) wire() {
	s.describe = newDescribeCase(&s.deps.Core, &s.deps.Describe, s.updateInfo)
	s.delivery = newDeliveryCase(&s.deps.Core, &s.deps.Delivery, liveApprovals{&s.deps.Approval}, s.Failure)
	s.approval = newApprovalCase(&s.deps.Core, &s.deps.Approval, s.delivery, serviceReverts{s}, liveWrites{&s.deps.Write}, s)
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
func (s *Service) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	run, err := s.startRun(ctx, intent, taskID)
	if err != nil {
		return RunInfo{}, err
	}
	run.Warnings = s.upgradeWarnings(ctx)
	return run, nil
}

// startRun is StartRun without the setup warnings, for the run a write
// starts for itself.
func (s *Service) startRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
	if taskID == uuid.Nil {
		taskID = newID()
	}
	run := RunInfo{RunID: newID(), TaskID: taskID, Intent: intent, StartedAt: s.deps.Core.Now().UTC()}
	if err := s.deps.Core.Store.StartRun(ctx, action.Intent{RunID: run.RunID, TaskID: taskID, Text: intent}); err != nil {
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
func (s *Service) Query(ctx context.Context, p QueryParams) (QueryOutcome, error) {
	run, err := findRun(ctx, s.deps.Core.Store, p.RunID)
	if err != nil {
		return QueryOutcome{}, err
	}
	in := action.Intent{RunID: run.ID, TaskID: run.TaskID, Text: run.Intent}
	start := s.deps.Core.Now()
	stmt, err := s.deps.Write.Store.Check(p.SQL, action.ToolQuery)
	if err == nil {
		err = checkArgs(stmt, p.Params)
	}
	if err != nil {
		return QueryOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	res, err := s.deps.Write.Store.Read(ctx, p.SQL, p.Params, stmt)
	if err != nil {
		return QueryOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	// The values of IDENTIFIER columns go in the dictionary before the rows
	// leave the engine (M5.1 plan, section 6). One that cannot be added
	// keeps the rows from the agent.
	if err := s.deps.Write.PII.Observe(ctx, res.Columns, res.Rows); err != nil {
		s.deps.Core.Log.Error("pii: the read's values could not be added to the dictionary; its rows are withheld", "err", err)
		// An engine failure, not the agent's SQL: INTERNAL even when a
		// Postgres error (a map reload) caused it. The cause is logged above.
		return QueryOutcome{}, &toolresult.ToolError{Code: guidance.CodeInternal, Message: "internal engine error"}
	}
	change, err := s.deps.Core.Store.RecordRead(ctx, action.Read{
		RunID: run.ID, Statement: p.SQL, Params: p.Params, Tables: stmt.Tables,
		Rows: len(res.Rows), Duration: res.Duration, Versions: res.Versions,
	})
	if err != nil {
		return QueryOutcome{}, fmt.Errorf("record read: %w", err)
	}
	return QueryOutcome{ReadResult: res, ChangeID: change, Warnings: s.rlsWarnings(ctx, stmt.Tables, len(res.Rows))}, nil
}

// History returns one page of a run's change records.
func (s *Service) History(ctx context.Context, p action.ChangeListParams) (History, error) {
	if _, err := findRun(ctx, s.deps.Core.Store, p.RunID); err != nil {
		return History{}, err
	}
	return s.deps.Core.Store.History(ctx, p)
}

// ListRuns returns one page of the agent's own runs with what each did.
func (s *Service) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return s.deps.Core.Store.ListRuns(ctx, p)
}

// runFinder is the ledger lookup of one run of the agent.
type runFinder interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
}

// findRun looks up the agent's run in its ledger: the zero run for uuid.Nil, or
// NOT_FOUND. Every domain that takes a runId goes through it.
func findRun(ctx context.Context, store runFinder, id uuid.UUID) (action.Run, error) {
	if id == uuid.Nil {
		return action.Run{}, nil
	}
	run, err := store.FindRun(ctx, id)
	if errors.Is(err, action.ErrRunNotFound) {
		return action.Run{}, &toolresult.ToolError{Code: guidance.CodeNotFound, Reason: guidance.ReasonRun, Message: fmt.Sprintf("run %s is not one of this agent's runs; start one with run_start", id)}
	}
	return run, err
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
func (s *Service) refused(ctx context.Context, in action.Intent, op action.Op, sql string, params []any, start time.Time, err error) error {
	te := guidance.MessageTooLarge(actionTool(op), err, s.deps.Core.Errors.ToolError(err))
	if !recorded(te.Code) {
		return err
	}
	r := action.Refusal{
		Intent: in, Op: refusalOp(op), Statement: sql, Params: params,
		Code: te.Code, Reason: truncate(te.Message, maxReasonBytes), Duration: s.deps.Core.Now().Sub(start),
	}
	if recErr := s.deps.Core.Store.RecordRefusal(context.WithoutCancel(ctx), r); recErr != nil {
		s.deps.Core.Log.Error("record refusal", "code", te.Code, "err", recErr)
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
