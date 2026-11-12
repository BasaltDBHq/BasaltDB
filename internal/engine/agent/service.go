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
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
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
	// LinkBudget is the longest long link, in characters of the whole URL,
	// handed to an agent as the way to open a page (CONTRACT.md, The link
	// budget); links.DefaultBudget when zero.
	LinkBudget int
	// Poll is how often a waiting call reads whether the person signed;
	// DefaultPoll when zero.
	Poll time.Duration
}

// Service runs one agent's tool calls.
type Service struct {
	Deps
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
	if d.LinkBudget <= 0 {
		d.LinkBudget = links.DefaultBudget
	}
	if d.Poll <= 0 {
		d.Poll = DefaultPoll
	}
	return &Service{Deps: d}
}

// RunInfo is a started run.
type RunInfo struct {
	RunID     uuid.UUID
	TaskID    uuid.UUID
	Intent    string
	StartedAt time.Time
}

// StartRun starts a run with intent. taskID joins a task another agent
// started; uuid.Nil starts a new task.
func (s *Service) StartRun(ctx context.Context, intent string, taskID uuid.UUID) (RunInfo, error) {
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
	change, err := s.Reads.RecordRead(ctx, guard.Read{
		RunID: run.ID, Statement: p.SQL, Params: p.Params, Tables: stmt.Tables,
		Rows: len(res.Rows), Duration: res.Duration, Versions: res.Versions,
	})
	if err != nil {
		return QueryOutcome{}, fmt.Errorf("record read: %w", err)
	}
	return QueryOutcome{ReadResult: res, ChangeID: change}, nil
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
	return WriteOutcome{WriteResult: res, RunID: run.ID, Op: stmt.Op}, nil
}

// writeRun finds the named run, or starts a one-write run.
func (s *Service) writeRun(ctx context.Context, p WriteParams) (agentdb.Run, error) {
	if p.RunID != uuid.Nil {
		return s.findRun(ctx, p.RunID)
	}
	info, err := s.StartRun(ctx, p.Intent, uuid.Nil)
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
	te := ToolError(err)
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
