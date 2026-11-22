// Package person holds what the person's commands read and relay with the
// agent's credential (Ledger, over a direct connection: DBLedger), and the
// engine-kept plugin entries' request and result types with their errors.
// The person socket that once served them in service mode is removed
// (CONTRACT.md, CLI, Removed).
package person

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Code is an error code of an engine-kept plugin change.
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

// Error is a refusal of an engine-kept plugin change, or another error of
// one, with its code.
type Error struct {
	Code Code `json:"code"`
	// Reason is set with CodePluginRefused only.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// Error is the message, as the same-user CLI prints the same failure.
func (e *Error) Error() string { return e.Message }

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
