package ledger

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// PersonDB is an agent-credential database handle: a pool in the engine, a
// connection in the CLI.
type PersonDB interface {
	guard.Querier
	guard.TxBeginner
}

// Person runs the person ledger calls on db with the agent's credential.
type Person struct {
	db  PersonDB
	now func() time.Time
}

// NewPerson is the Person over db. Every transaction it begins is pinned
// (guard.PinSession); the calls that build row images or lines (preview,
// prepare, apply and rescope of a revert) run in one, so the person's
// session zone and styles change neither the lines nor the conflict check.
func NewPerson(db PersonDB, now func() time.Time) *Person {
	if db == nil || now == nil {
		panic("ledger: db and clock required")
	}
	return &Person{db: guard.Pinned(db), now: now}
}

// CheckHealth is CheckHealth now.
func (l *Person) CheckHealth(ctx context.Context, opts HealthOptions) (Health, error) {
	return CheckHealth(ctx, l.db, l.now(), opts)
}

// ListChanges is ListChanges.
func (l *Person) ListChanges(ctx context.Context, p ChangeListParams) (pagination.Page[Change], error) {
	return ListChanges(ctx, l.db, p)
}

// ListAccess is pgcatalog.ListAccess: session_user's privileges, so the
// agent's own.
func (l *Person) ListAccess(ctx context.Context) (pgcatalog.Access, error) {
	return pgcatalog.ListAccess(ctx, l.db)
}

// RowChanges is RowChanges.
func (l *Person) RowChanges(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]RowChange, error) {
	return RowChanges(ctx, l.db, ids)
}

// ListPasskeys is ListPasskeys.
func (l *Person) ListPasskeys(ctx context.Context) ([]Passkey, error) {
	return ListPasskeys(ctx, l.db)
}

// FindApproval is FindApproval.
func (l *Person) FindApproval(ctx context.Context, id uuid.UUID) (Approval, error) {
	return FindApproval(ctx, l.db, id)
}

// SubmitApproval is guard.SubmitApproval.
func (l *Person) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	return guard.SubmitApproval(ctx, l.db, id, a)
}

// FindRevert is FindRevert.
func (l *Person) FindRevert(ctx context.Context, id uuid.UUID) (Revert, error) {
	return FindRevert(ctx, l.db, id)
}

// PreviewRevert is guard.PreviewRevert, in a pinned transaction.
func (l *Person) PreviewRevert(ctx context.Context, s guardmodel.RevertScope) ([]string, error) {
	var lines []string
	err := pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		lines, err = guard.PreviewRevert(ctx, tx, s)
		return err
	})
	return lines, err
}

// PrepareRevert is guard.PrepareRevertWithin the CLI's time limit.
func (l *Person) PrepareRevert(ctx context.Context, s guardmodel.RevertScope, intent string) (guardmodel.PreparedRevert, error) {
	return guard.PrepareRevertWithin(ctx, l.db, s, intent, guardmodel.CLIPrepareTimeout)
}

// ApplyRevert is guard.ApplyRevert, in its own pinned transaction.
func (l *Person) ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guardmodel.AppliedRevert, error) {
	var out guardmodel.AppliedRevert
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
func (l *Person) RescopeRevert(ctx context.Context, id uuid.UUID, runs []uuid.UUID, tables []string) (guardmodel.PreparedRevert, error) {
	r, err := FindRevert(ctx, l.db, id)
	if err != nil {
		return guardmodel.PreparedRevert{}, err
	}
	scope := guardmodel.RevertScope{Kind: revert.Scope(r.Scope), ID: r.ScopeID, Runs: runs, Tables: tables}
	var out guardmodel.PreparedRevert
	err = pgx.BeginTxFunc(ctx, l.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		out, err = guard.RescopeOwn(ctx, tx, id, scope)
		return err
	})
	return out, err
}

// RejectRevert is guard.RejectRevert with no scope token: it never rejects
// a revert the person widened.
func (l *Person) RejectRevert(ctx context.Context, id uuid.UUID, note string) (guardmodel.RejectedRevert, error) {
	return guard.RejectRevert(ctx, l.db, id, note, nil)
}

// ListRevertLines is ListRevertLines.
func (l *Person) ListRevertLines(ctx context.Context, p RevertLineParams) (pagination.Page[RevertLine], error) {
	return ListRevertLines(ctx, l.db, p)
}
