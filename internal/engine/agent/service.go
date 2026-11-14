// Package agent is what the engine does for one agent: the tool services
// (policy check, then one statement on the agent's scoped credential,
// writes through the guard) and the MCP tools that front them, built from
// the contracts in api/mcp.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// Limits of the guard's validating ledger functions (CONTRACT.md,
// basalt_meta): statements and parameters up to 64 KiB, reasons up to
// 2000 bytes.
const (
	maxParamsBytes = 64 << 10
	maxReasonBytes = 2000

	// opOther is the refusal op of a statement that is not one of the four.
	opOther = "OTHER"
)

// Reader runs one read on the agent's credential, with the versions of the
// rows of sources it can identify.
type Reader interface {
	Read(ctx context.Context, sql string, params []any, sources []sqlguard.RowSource) (agentdb.ReadResult, error)
}

// Store runs writes through the guard and reads runs and change records.
type Store interface {
	FindRun(ctx context.Context, id uuid.UUID) (agentdb.Run, error)
	StartRun(ctx context.Context, in guard.Intent) error
	Write(ctx context.Context, in guard.Intent, op sqlguard.Op, sql string, params []any) (agentdb.WriteResult, error)
	RecordRefusal(ctx context.Context, r guard.Refusal) error
	History(ctx context.Context, p ledger.ChangeListParams) (agentdb.History, error)
	ListRuns(ctx context.Context, p ledger.RunListParams) (pagination.Page[agentdb.RunSummary], error)
}

// ReadRecorder records the reads the engine runs (owner decision #7) and
// returns the read's change id. It runs after the read's own read-only
// transaction, so it may write.
type ReadRecorder interface {
	RecordRead(ctx context.Context, r guard.Read) (uuid.UUID, error)
}

// Deps are a Service's dependencies, all required.
type Deps struct {
	Name   string
	Reader Reader
	Store  Store
	Reads  ReadRecorder
	Log    *slog.Logger
	Now    func() time.Time
	// Approvals holds and applies writes that need the person's approval.
	Approvals ApprovalStore
	// Reverts previews reverts (M3).
	Reverts RevertStore
	// Notifier is optional: no notification when nil.
	Notifier Notifier
	// PagesBase is the base URL of the approval and revert pages (links);
	// links.DefaultLocal when empty.
	PagesBase string
	// Commands builds the commands the person runs for this agent; the
	// default ones for Name and the platform's default config when zero.
	Commands Commands
	// PagesOrigin is the origin of the pages the engine serves itself
	// (CONTRACT.md, Local pages), for short links; empty when it serves
	// none, and held actions then carry the long link.
	PagesOrigin string
	// Links holds the short links' secrets, shared with the pages; a store
	// of its own when nil.
	Links *links.Secrets
	// Relay registers portal short links with the Vault; optional, none
	// when nil (the Vault is off).
	Relay LinkRelay
	// LinkBudget is the longest long link, in characters of the whole URL,
	// handed to an agent as the way to open a page (CONTRACT.md, The link
	// budget); links.DefaultBudget when zero.
	LinkBudget int
	// Poll is how often a waiting call reads whether the person signed;
	// DefaultPoll when zero.
	Poll time.Duration
	// RLS says whether row-level security hides a table from the agent
	// (the RLS_HIDES_ROWS warning); optional, nothing is hidden when nil.
	RLS RLSChecker
	// Upgrade says whether only non-breaking guard migrations are missing
	// (the GUARD_UPGRADE_AVAILABLE warning); optional, Probe answers when nil.
	Upgrade UpgradeChecker

	// What the status tool reports beyond the database, all optional
	// (CONTRACT.md, MCP tools, status). OperatedBy is engine.json operatedBy
	// (PERSON when empty); SameUser is an engine run as the person's own OS
	// user (enforcement GUARD_ONLY); Setup is the agent's pending setup code
	// from the config; Build is the engine's build (buildinfo.Version when
	// empty).
	OperatedBy string
	SameUser   bool
	// DevLocalPages is engine.json devLocalPages: every personMessage starts
	// with the DEV_LOCAL_PAGES warning and status reports the problem
	// (CONTRACT.md, Page origins).
	DevLocalPages bool
	Setup         *config.Setup
	Build         string
	// Probe reads the guard's state and the agent's setups on its
	// credential, for status and to admit each call; a current guard when
	// nil.
	Probe Probe
	// Vault reports the engine's Vault connection for status; status leaves
	// vault out when nil.
	Vault VaultReporter
	// EngineRecord reads this engine's row in the agent's database for the
	// status tool's engineRecord; nil makes its state UNKNOWN. DirectServed
	// is whether the engine has a direct listener (directAddr is not off).
	EngineRecord EngineRecordReader
	DirectServed bool
	// Receipts is the engine's signing key, which signs the receipt of
	// every signature the engine relays (CONTRACT.md, Vault channel,
	// Receipts). Nil when the key file is refused (KEY_ERROR): answers then
	// carry noReceipt.
	Receipts ReceiptSigner
	// Finisher finishes a setup the database shows recorded: it promotes a
	// rotated credential and clears setup from engine.json. Optional: the
	// setup is then only forgotten in memory.
	Finisher SetupFinisher
	// PII sees every read's rows before they are returned and adds the
	// values of IDENTIFIER columns to the dictionary (M5.1); optional,
	// nothing is added when nil.
	PII PIIObserver
	// Catalog reads the database's structure for describe; optional, and
	// describe answers INTERNAL when nil.
	Catalog Catalog
	// Columns reads each table's columns in table order for the pages;
	// optional, and the pages show the order the rows carry when nil.
	Columns ColumnOrder
	// Classes are the agent's PII classes for describe; optional, and
	// describe fails closed (INTERNAL) when nil: it cannot tell a SECRET
	// column.
	Classes ClassResolver
}

// PIIObserver adds the PII values of rows the agent is about to get to the
// engine's dictionary. An error means a value could not be added: the rows
// are not returned (fail closed). It never logs a value.
type PIIObserver interface {
	Observe(ctx context.Context, cols []agentdb.Column, rows []map[string]any) error
}

type noPII struct{}

func (noPII) Observe(context.Context, []agentdb.Column, []map[string]any) error { return nil }

// Service runs one agent's tool calls.
type Service struct {
	Deps
	// setupMu guards setup, the agent's pending setup: Deps.Setup until the
	// database shows it recorded.
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
}

// NewService returns the service for one agent. It panics on a missing
// dependency.
func NewService(d Deps) *Service {
	if d.Name == "" || d.Reader == nil || d.Store == nil || d.Reads == nil || d.Log == nil || d.Now == nil ||
		d.Approvals == nil || d.Reverts == nil {
		panic("agent: name, reader, store, read recorder, approval and revert stores, logger and clock required")
	}
	if d.Notifier == nil {
		d.Notifier = noNotifier{}
	}
	if d.RLS == nil {
		d.RLS = noRLS{}
	}
	if d.Probe == nil {
		d.Probe = noProbe{}
	}
	if d.Finisher == nil {
		d.Finisher = noFinisher{}
	}
	if d.Upgrade == nil {
		d.Upgrade = guardUpgrade{probe: d.Probe}
	}
	if d.Build == "" {
		d.Build = buildinfo.Version
	}
	if d.Relay == nil {
		d.Relay = noRelay{}
	}
	if d.PII == nil {
		d.PII = noPII{}
	}
	if d.Catalog == nil {
		d.Catalog = noCatalog{}
	}
	if d.Classes == nil {
		d.Classes = noClasses{}
	}
	if d.PagesBase == "" {
		d.PagesBase = links.DefaultLocal
	}
	if d.Links == nil {
		d.Links = links.NewSecrets(time.Now, rand.Reader)
	}
	if d.Commands.flags == "" {
		// A name and no config path or init arguments cannot fail.
		d.Commands, _ = NewCommands(d.Name, "", "", nil)
	}
	d.Commands = d.Commands.OperatedBy(d.OperatedBy)
	if d.LinkBudget <= 0 {
		d.LinkBudget = links.DefaultBudget
	}
	if d.Poll <= 0 {
		d.Poll = DefaultPoll
	}
	return &Service{Deps: d, setup: d.Setup, rescopes: newRescopes()}
}

// RunInfo is a started run.
type RunInfo struct {
	RunID     uuid.UUID
	TaskID    uuid.UUID
	Intent    string
	StartedAt time.Time
	// Warnings are what the person should hear about the setup, with the
	// steps for it (GUARD_UPGRADE_AVAILABLE).
	Warnings []mcp.Warning
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
	run := RunInfo{RunID: newID(), TaskID: taskID, Intent: intent, StartedAt: s.Now().UTC()}
	if err := s.Store.StartRun(ctx, guard.Intent{RunID: run.RunID, TaskID: taskID, Text: intent}); err != nil {
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
	agentdb.ReadResult
	ChangeID uuid.UUID
	Warnings []mcp.Warning
}

// Query checks sql against the policy, runs it read-only within the limits
// and records the read with the version of each row it could identify. A
// refused or failed statement is recorded as a REFUSED change. A read that
// cannot be recorded is not returned: the ledger must know what the agent
// saw.
func (s *Service) Query(ctx context.Context, p QueryParams) (QueryOutcome, error) {
	run, err := s.findRun(ctx, p.RunID)
	if err != nil {
		return QueryOutcome{}, err
	}
	in := guard.Intent{RunID: run.ID, TaskID: run.TaskID, Text: run.Intent}
	start := s.Now()
	stmt, err := sqlguard.Check(p.SQL, sqlguard.ToolQuery)
	if err == nil {
		err = checkArgs(stmt, p.Params)
	}
	if err != nil {
		return QueryOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	res, err := s.Reader.Read(ctx, p.SQL, p.Params, stmt.RowSources)
	if err != nil {
		return QueryOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	// The values of IDENTIFIER columns go in the dictionary before the rows
	// leave the engine (M5.1 plan, section 6). One that cannot be added
	// keeps the rows from the agent.
	if err := s.PII.Observe(ctx, res.Columns, res.Rows); err != nil {
		s.Log.Error("pii: the read's values could not be added to the dictionary; its rows are withheld", "err", err)
		// An engine failure, not the agent's SQL: INTERNAL even when a
		// Postgres error (a map reload) caused it. The cause is logged above.
		return QueryOutcome{}, &mcp.ToolError{Code: CodeInternal, Message: "internal engine error"}
	}
	change, err := s.Reads.RecordRead(ctx, guard.Read{
		RunID: run.ID, Statement: p.SQL, Params: p.Params, Tables: stmt.Tables,
		Rows: len(res.Rows), Duration: res.Duration, Versions: res.Versions,
	})
	if err != nil {
		return QueryOutcome{}, fmt.Errorf("record read: %w", err)
	}
	return QueryOutcome{ReadResult: res, ChangeID: change, Warnings: s.rlsWarnings(ctx, stmt.Tables, len(res.Rows))}, nil
}

// WriteParams are one write call's validated arguments.
type WriteParams struct {
	SQL    string
	Params []any
	Intent string
	RunID  uuid.UUID // uuid.Nil starts a one-write run with the intent
	// ApprovalID applies a held write; Approval is the person's signed
	// code, relayed when given.
	ApprovalID uuid.UUID
	Approval   string
	// Wait is how long to wait for the person to sign a held write before
	// answering APPROVAL_REQUIRED (CONTRACT.md, Waiting write); 0 answers
	// at once.
	Wait time.Duration
}

// WriteOutcome is one applied write.
type WriteOutcome struct {
	agentdb.WriteResult
	RunID uuid.UUID
	Op    sqlguard.Op
	// ApprovalID is set when the write applied under an approval.
	ApprovalID uuid.UUID
	Warnings   []mcp.Warning
	// Receipt is the approval's receipt when the write applied under one.
	Receipt *Receipt
}

// Write checks sql against the policy and runs it through the guard with
// the intent. A refused or failed write is recorded as a REFUSED change.
func (s *Service) Write(ctx context.Context, p WriteParams) (WriteOutcome, error) {
	if p.ApprovalID != uuid.Nil {
		return s.applyApproved(ctx, p)
	}
	run, err := s.writeRun(ctx, p)
	if err != nil {
		return WriteOutcome{}, err
	}
	in := guard.Intent{RunID: run.ID, TaskID: run.TaskID, Text: p.Intent}
	start := s.Now()
	stmt, err := sqlguard.Check(p.SQL, sqlguard.ToolWrite)
	if err == nil {
		err = checkArgs(stmt, p.Params)
	}
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	res, err := s.Store.Write(ctx, in, stmt.Op, p.SQL, p.Params)
	if approvalRequired(err) {
		id, err := s.hold(ctx, in, p, stmt, start)
		if id == uuid.Nil || p.Wait == 0 {
			return WriteOutcome{}, err
		}
		// Held: wait for the person's signature and apply it, exactly as
		// the repeat with approvalId would. On timeout the answer is the
		// hold's own, which carries the link just issued.
		p.ApprovalID, p.RunID = id, run.ID
		out, waitErr := s.applyApproved(ctx, p)
		var te *mcp.ToolError
		if errors.As(waitErr, &te) && te.Code == CodeApprovalRequired {
			return WriteOutcome{}, err
		}
		return out, waitErr
	}
	if err != nil {
		return WriteOutcome{}, s.refused(ctx, in, stmt.Op, p.SQL, p.Params, start, err)
	}
	return WriteOutcome{WriteResult: res, RunID: run.ID, Op: stmt.Op, Warnings: s.rlsWarnings(ctx, stmt.Tables, res.Rows)}, nil
}

// writeRun finds the named run, or starts a one-write run.
func (s *Service) writeRun(ctx context.Context, p WriteParams) (agentdb.Run, error) {
	if p.RunID != uuid.Nil {
		return s.findRun(ctx, p.RunID)
	}
	info, err := s.startRun(ctx, p.Intent, uuid.Nil)
	if err != nil {
		return agentdb.Run{}, err
	}
	return agentdb.Run{ID: info.RunID, TaskID: info.TaskID, Intent: info.Intent}, nil
}

// History returns one page of a run's change records.
func (s *Service) History(ctx context.Context, p ledger.ChangeListParams) (agentdb.History, error) {
	if _, err := s.findRun(ctx, p.RunID); err != nil {
		return agentdb.History{}, err
	}
	return s.Store.History(ctx, p)
}

// ListRuns returns one page of the agent's own runs with what each did.
func (s *Service) ListRuns(ctx context.Context, p ledger.RunListParams) (pagination.Page[agentdb.RunSummary], error) {
	return s.Store.ListRuns(ctx, p)
}

// findRun returns the agent's run, the zero run for uuid.Nil, or NOT_FOUND.
func (s *Service) findRun(ctx context.Context, id uuid.UUID) (agentdb.Run, error) {
	if id == uuid.Nil {
		return agentdb.Run{}, nil
	}
	run, err := s.Store.FindRun(ctx, id)
	if errors.Is(err, agentdb.ErrRunNotFound) {
		return agentdb.Run{}, &mcp.ToolError{Code: CodeNotFound, Reason: reasonRun, Message: fmt.Sprintf("run %s is not one of this agent's runs; start one with run_start", id)}
	}
	return run, err
}

// recorded reports whether a failure is an action the ledger keeps as
// REFUSED: anything the policy, the guard or the database refused. Bad
// arguments, a missing run, and an unreachable database are not actions.
func recorded(code string) bool {
	switch code {
	case CodeInvalidArgument, CodeNotFound, CodeUnavailable, CodeInternal:
		return false
	}
	return true
}

// refused records a REFUSED change for err when it is an action the ledger
// keeps, and returns err. A failure to record is logged; the agent still
// gets the original refusal.
func (s *Service) refused(ctx context.Context, in guard.Intent, op sqlguard.Op, sql string, params []any, start time.Time, err error) error {
	te := messageTooLarge(actionTool(op), err, ToolError(err))
	if !recorded(te.Code) {
		return err
	}
	r := guard.Refusal{
		Intent: in, Op: refusalOp(op), Statement: sql, Params: params,
		Code: te.Code, Reason: truncate(te.Message, maxReasonBytes), Duration: s.Now().Sub(start),
	}
	if recErr := s.Store.RecordRefusal(context.WithoutCancel(ctx), r); recErr != nil {
		s.Log.Error("record refusal", "code", te.Code, "err", recErr)
	}
	return err
}

// actionTool is the tool an action came from: query runs only a SELECT
// (sqlguard refuses anything else as WRONG_TOOL), write everything else.
// Failure maps the error by tool, so a refusal is recorded with the code
// the agent gets.
func actionTool(op sqlguard.Op) string {
	if op == sqlguard.OpSelect {
		return toolQuery
	}
	return toolWrite
}

// refusalOp is the op the guard's record_refusal accepts.
func refusalOp(op sqlguard.Op) string {
	switch op {
	case sqlguard.OpSelect, sqlguard.OpInsert, sqlguard.OpUpdate, sqlguard.OpDelete:
		return string(op)
	case sqlguard.OpMerge:
		return opOther
	}
	return opOther
}

// checkArgs checks the parameters match the statement's placeholders and
// fit the guard's ledger limit.
func checkArgs(stmt sqlguard.Statement, params []any) error {
	if stmt.ParamCount != len(params) {
		return &ArgumentError{Message: fmt.Sprintf("the statement uses %d parameters ($1..$%d) but %d were given",
			stmt.ParamCount, stmt.ParamCount, len(params))}
	}
	raw, err := json.Marshal(params)
	if err != nil || len(raw) > maxParamsBytes {
		return &ArgumentError{Message: "params must encode to at most 64 KiB of JSON"}
	}
	return nil
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
