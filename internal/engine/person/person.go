// Package person is the person socket (CONTRACT.md, The person socket;
// owner decisions SM-1 to SM-3). In service mode the engine runs as its own
// OS user and the person's basalt log, approve and revert cannot read its
// config or the agent's credential, so they ask the running engine over
// <socket dir>/person.sock. The engine admits only the person uids recorded
// at basalt init, checked on every connection before a byte is read, and
// runs each request with the agent's own credential. It serves only what
// those commands need, never the MCP tools, and never returns the
// credential or the config.
//
// The same Ledger interface backs the CLI in both modes: DBLedger over a
// direct connection (same-user mode) and AgentClient over the socket
// (service mode).
package person

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// ProtocolVersion is the greeting's version.
const ProtocolVersion = 1

// Method names a person socket request.
type Method string

// Methods (CONTRACT.md, The person socket).
const (
	MethodPages           Method = "PAGES"
	MethodCheckHealth     Method = "CHECK_HEALTH"
	MethodListChanges     Method = "LIST_CHANGES"
	MethodListAccess      Method = "LIST_ACCESS"
	MethodRowChanges      Method = "ROW_CHANGES"
	MethodListPasskeys    Method = "LIST_PASSKEYS"
	MethodFindApproval    Method = "FIND_APPROVAL"
	MethodSubmitApproval  Method = "SUBMIT_APPROVAL"
	MethodFindRevert      Method = "FIND_REVERT"
	MethodPreviewRevert   Method = "PREVIEW_REVERT"
	MethodPrepareRevert   Method = "PREPARE_REVERT"
	MethodApplyRevert     Method = "APPLY_REVERT"
	MethodListRevertLines Method = "LIST_REVERT_LINES"
	MethodRescopeRevert   Method = "RESCOPE_REVERT"
	MethodRejectRevert    Method = "REJECT_REVERT"
	MethodStatus          Method = "STATUS"
	MethodTarget          Method = "TARGET"
	MethodAgents          Method = "AGENTS"
)

// Code is an error code of the person socket.
type Code string

// Error codes.
const (
	CodeUIDNotAllowed   Code = "UID_NOT_ALLOWED"
	CodeUnknownAgent    Code = "UNKNOWN_AGENT"
	CodeAgentNotAllowed Code = "AGENT_NOT_ALLOWED"
	CodeUnknownMethod   Code = "UNKNOWN_METHOD"
	CodeInvalidArgument Code = "INVALID_ARGUMENT"
	CodeNotFound        Code = "NOT_FOUND"
	CodeRefused         Code = "REFUSED"
	CodeInternal        Code = "INTERNAL"
)

// Limits and timeouts of the protocol.
const (
	// MaxRequestBytes bounds one request line.
	MaxRequestBytes = 256 << 10
	// maxResponseBytes bounds one response line the client reads: a page
	// of 200 changes with their rows, or a prepared revert's lines.
	maxResponseBytes = 64 << 20
	// RequestTimeout is how long the engine waits for the request after
	// the greeting, and how long the client waits for the greeting.
	RequestTimeout = 10 * time.Second
	// callTimeout bounds every method but PREPARE_REVERT.
	callTimeout = 2 * time.Minute
	// writeTimeout bounds writing one response.
	writeTimeout = 30 * time.Second
	// MaxConns is how many person connections the engine serves at once.
	MaxConns = 16
)

// methodTimeout is how long the engine gives method: preparing a revert
// may take guard.CLIPrepareTimeout, as for the same-user CLI.
func methodTimeout(m Method) time.Duration {
	if m == MethodPrepareRevert {
		return guard.CLIPrepareTimeout + callTimeout
	}
	if pluginMethod(m) {
		return pluginTimeout
	}
	return callTimeout
}

// Greeting is the engine's first line on a connection.
type Greeting struct {
	OK      bool   `json:"ok"`
	Version int    `json:"version"`
	Error   *Error `json:"error,omitempty"`
}

// Request is one call.
type Request struct {
	Method Method          `json:"method"`
	Agent  string          `json:"agent,omitempty"`
	Params json.RawMessage `json:"params"`
	// agentSet: the request line holds an agent key, even empty.
	agentSet bool
}

// Response is the engine's answer: Result or Error.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is a person socket error.
type Error struct {
	Code Code `json:"code"`
	// Reason is set with CodePluginRefused only.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// Error is the message, as the same-user CLI prints the same failure.
func (e *Error) Error() string { return e.Message }

// ErrNotRunning is a socket that is missing or refuses the connection:
// the engine is not running.
var ErrNotRunning = errors.New("the engine is not running")

// ErrUIDNotAllowed is the engine refusing this OS user on its person socket.
var ErrUIDNotAllowed = errors.New("the engine does not admit this OS user on its person socket")

// Ledger is what the person's log, approve and revert read and relay with
// the agent's credential. DBLedger runs it on a connection; AgentClient asks
// the engine.
type Ledger interface {
	CheckHealth(ctx context.Context, opts ledger.HealthOptions) (ledger.Health, error)
	ListChanges(ctx context.Context, p ledger.ChangeListParams) (pagination.Page[ledger.Change], error)
	ListAccess(ctx context.Context) (pgcatalog.Access, error)
	RowChanges(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error)
	ListPasskeys(ctx context.Context) ([]ledger.Passkey, error)
	FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error)
	SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error)
	FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error)
	PreviewRevert(ctx context.Context, s guard.RevertScope) ([]string, error)
	PrepareRevert(ctx context.Context, s guard.RevertScope, intent string) (guard.PreparedRevert, error)
	ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error)
	ListRevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error)
	RescopeRevert(ctx context.Context, id uuid.UUID, runs []uuid.UUID, tables []string) (guard.PreparedRevert, error)
	RejectRevert(ctx context.Context, id uuid.UUID, note string) (guard.RejectedRevert, error)
}

// DB is an agent-credential database handle: a pool in the engine, a
// connection in the CLI.
type DB interface {
	guard.Querier
	guard.TxBeginner
}

// DBLedger runs the Ledger calls on db with the agent's credential.
type DBLedger struct {
	db  DB
	now func() time.Time
}

// NewDBLedger is the Ledger over db. Every transaction it begins is pinned
// (guard.PinSession); the calls that build row images or lines (preview,
// prepare, apply and rescope of a revert) run in one, so the person's
// session zone and styles change neither the lines nor the conflict check.
func NewDBLedger(db DB, now func() time.Time) *DBLedger {
	if db == nil || now == nil {
		panic("person: db and clock required")
	}
	return &DBLedger{db: guard.Pinned(db), now: now}
}

// CheckHealth is ledger.CheckHealth now.
func (l *DBLedger) CheckHealth(ctx context.Context, opts ledger.HealthOptions) (ledger.Health, error) {
	return ledger.CheckHealth(ctx, l.db, l.now(), opts)
}

// ListChanges is ledger.ListChanges.
func (l *DBLedger) ListChanges(ctx context.Context, p ledger.ChangeListParams) (pagination.Page[ledger.Change], error) {
	return ledger.ListChanges(ctx, l.db, p)
}

// ListAccess is pgcatalog.ListAccess: session_user's privileges, so the
// agent's own.
func (l *DBLedger) ListAccess(ctx context.Context) (pgcatalog.Access, error) {
	return pgcatalog.ListAccess(ctx, l.db)
}

// RowChanges is ledger.RowChanges.
func (l *DBLedger) RowChanges(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error) {
	return ledger.RowChanges(ctx, l.db, ids)
}

// ListPasskeys is ledger.ListPasskeys.
func (l *DBLedger) ListPasskeys(ctx context.Context) ([]ledger.Passkey, error) {
	return ledger.ListPasskeys(ctx, l.db)
}

// FindApproval is ledger.FindApproval.
func (l *DBLedger) FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	return ledger.FindApproval(ctx, l.db, id)
}

// SubmitApproval is guard.SubmitApproval.
func (l *DBLedger) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	return guard.SubmitApproval(ctx, l.db, id, a)
}

// FindRevert is ledger.FindRevert.
func (l *DBLedger) FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	return ledger.FindRevert(ctx, l.db, id)
}

// PreviewRevert is guard.PreviewRevert, in a pinned transaction.
func (l *DBLedger) PreviewRevert(ctx context.Context, s guard.RevertScope) ([]string, error) {
	var lines []string
	err := pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		lines, err = guard.PreviewRevert(ctx, tx, s)
		return err
	})
	return lines, err
}

// PrepareRevert is guard.PrepareRevertWithin the CLI's time limit.
func (l *DBLedger) PrepareRevert(ctx context.Context, s guard.RevertScope, intent string) (guard.PreparedRevert, error) {
	return guard.PrepareRevertWithin(ctx, l.db, s, intent, guard.CLIPrepareTimeout)
}

// ApplyRevert is guard.ApplyRevert, in its own pinned transaction.
func (l *DBLedger) ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error) {
	var out guard.AppliedRevert
	err := pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		out, err = guard.ApplyRevert(ctx, tx, id, a)
		return err
	})
	return out, err
}

// RescopeRevert narrows the agent's own pending revert id to runs and
// tables (nil for all) inside the agent's own work, keeping its scope kind
// and id: guard.RescopeOwn, which never widens.
func (l *DBLedger) RescopeRevert(ctx context.Context, id uuid.UUID, runs []uuid.UUID, tables []string) (guard.PreparedRevert, error) {
	r, err := ledger.FindRevert(ctx, l.db, id)
	if err != nil {
		return guard.PreparedRevert{}, err
	}
	scope := guard.RevertScope{Kind: revert.Scope(r.Scope), ID: r.ScopeID, Runs: runs, Tables: tables}
	var out guard.PreparedRevert
	err = pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		out, err = guard.RescopeOwn(ctx, tx, id, scope)
		return err
	})
	return out, err
}

// RejectRevert is guard.RejectRevert with no scope token: it never rejects
// a revert the person widened.
func (l *DBLedger) RejectRevert(ctx context.Context, id uuid.UUID, note string) (guard.RejectedRevert, error) {
	return guard.RejectRevert(ctx, l.db, id, note, nil)
}

// ListRevertLines is ledger.ListRevertLines.
func (l *DBLedger) ListRevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	return ledger.ListRevertLines(ctx, l.db, p)
}
