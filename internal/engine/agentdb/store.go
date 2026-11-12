package agentdb

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// DB is the part of a pgx pool the store needs.
type DB interface {
	guard.Querier
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// Store runs one agent's writes through the guard and reads its runs and
// change records, always on the agent's own credential.
type Store struct {
	db       DB
	limits   sqlguard.Limits
	now      func() time.Time
	returned ReturnedFunc
}

// ReturnedFunc sees the rows a write returns (RETURNING) inside the write's
// transaction, before COMMIT: the engine adds their PII values to the
// dictionary there. An error rolls the write back, so no value it could not
// handle is applied or returned (fail closed).
type ReturnedFunc func(ctx context.Context, tx pgx.Tx, cols []Column, rows []map[string]any) error

// NewStore returns a store on db. It panics on a nil db or clock.
func NewStore(db DB, limits sqlguard.Limits, now func() time.Time) *Store {
	if db == nil || now == nil {
		panic("agentdb: db and clock required")
	}
	return &Store{db: db, limits: limits, now: now, returned: noReturned}
}

func noReturned(context.Context, pgx.Tx, []Column, []map[string]any) error { return nil }

// WithReturned has every write hand its returned rows to f before COMMIT.
// It panics on a nil f.
func (s *Store) WithReturned(f ReturnedFunc) *Store {
	if f == nil {
		panic("agentdb: nil returned-rows hook")
	}
	s.returned = f
	return s
}

// Run is one of the agent's runs.
type Run struct {
	ID     uuid.UUID
	TaskID uuid.UUID // uuid.Nil when the run has no task
	Intent string
}

// ErrRunNotFound is a run id that is not one of this agent's runs.
var ErrRunNotFound = errors.New("run not found")

// FindRun returns the agent's run id, read through the guard's agent view.
func (s *Store) FindRun(ctx context.Context, id uuid.UUID) (Run, error) {
	q, args, err := psql.Select("task_id", "intent").From("basalt_meta.agent_runs").
		Where(sq.Eq{"run_id": id.String()}).ToSql()
	if err != nil {
		return Run{}, err
	}
	run := Run{ID: id}
	var task uuid.NullUUID
	err = s.db.QueryRow(ctx, q, args...).Scan(&task, &run.Intent)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if task.Valid {
		run.TaskID = task.UUID
	}
	return run, err
}

// StartRun records a run and its RUN_STARTED ledger row.
func (s *Store) StartRun(ctx context.Context, in guard.Intent) error {
	return guard.StartRun(ctx, s.db, in)
}

// WriteResult is one applied write.
type WriteResult struct {
	ChangeID uuid.UUID
	// Rows is what the guard counted for the action, cascades included.
	Rows      int
	Duration  time.Duration
	Columns   []Column
	Returning []map[string]any
}

// Write runs one INSERT, UPDATE or DELETE in a guarded transaction (the
// engine session protocol): the time limit and the intent set
// transaction-local, the statement as given with its parameters, then the
// change stamped with statement, parameters and duration before COMMIT. Any
// error rolls the whole action back.
func (s *Store) Write(ctx context.Context, in guard.Intent, op sqlguard.Op, sql string, params []any) (WriteResult, error) {
	return s.write(ctx, op, sql, params, func(tx pgx.Tx) error { return guard.BeginGuarded(ctx, tx, in) })
}

// WriteApproved is Write under a signed approval (basalt.approval_id). The
// guard commits it only if it is the write the person approved.
func (s *Store) WriteApproved(ctx context.Context, in guard.Intent, approvalID uuid.UUID, op sqlguard.Op, sql string, params []any) (WriteResult, error) {
	return s.write(ctx, op, sql, params, func(tx pgx.Tx) error { return guard.BeginApproved(ctx, tx, in, approvalID) })
}

func (s *Store) write(ctx context.Context, op sqlguard.Op, sql string, params []any, begin func(pgx.Tx) error) (WriteResult, error) {
	start := s.now()
	var res WriteResult
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		if err := begin(tx); err != nil {
			return err
		}
		cols, rows, _, err := runText(ctx, tx, sql, params, s.limits.ReadRowLimit, 0)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			if err := s.returned(ctx, tx, cols, rows); err != nil {
				return err
			}
		}
		res.Columns, res.Returning = cols, rows
		res.Duration = s.now().Sub(start)
		res.ChangeID, err = guard.FinishChange(ctx, tx, guard.Finish{Op: string(op), Statement: sql, Params: params, Duration: res.Duration})
		if err != nil {
			return err
		}
		return s.countRows(ctx, tx, res.ChangeID, &res.Rows)
	})
	if err != nil {
		return WriteResult{}, err
	}
	return res, nil
}

func (s *Store) countRows(ctx context.Context, tx pgx.Tx, change uuid.UUID, rows *int) error {
	q, args, err := psql.Select("rows").From("basalt_meta.agent_changes").
		Where(sq.Eq{"change_id": change.String()}).ToSql()
	if err != nil {
		return err
	}
	return tx.QueryRow(ctx, q, args...).Scan(rows)
}

// RecordRead records a read the reader ran (a SELECT change record, the
// READ ledger row and the run's row versions) in its own transaction, and
// returns its change id.
func (s *Store) RecordRead(ctx context.Context, r guard.Read) (uuid.UUID, error) {
	return guard.RecordRead(ctx, s.db, r)
}

// RecordRefusal writes a REFUSED change record in its own transaction.
func (s *Store) RecordRefusal(ctx context.Context, r guard.Refusal) error {
	_, err := guard.RecordRefusal(ctx, s.db, r)
	return err
}

// History is one page of a run's change records with the rows each wrote.
type History struct {
	Page pagination.Page[ledger.Change]
	Rows map[uuid.UUID][]ledger.RowChange
}

// History reads one page of change records through the agent views.
func (s *Store) History(ctx context.Context, p ledger.ChangeListParams) (History, error) {
	page, err := ledger.ListChanges(ctx, s.db, p)
	if err != nil {
		return History{}, err
	}
	ids := make([]uuid.UUID, 0, len(page.Items))
	for _, ch := range page.Items {
		ids = append(ids, ch.ID)
	}
	rows, err := ledger.RowChanges(ctx, s.db, ids)
	if err != nil {
		return History{}, err
	}
	return History{Page: page, Rows: rows}, nil
}
