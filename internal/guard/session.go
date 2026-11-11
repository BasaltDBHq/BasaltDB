package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// psql builds calls with Postgres placeholders.
var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// Values of basalt.mode.
const (
	ModeApply   = "APPLY"
	ModePreview = "PREVIEW"
)

// ErrInvalidIntent is returned for an Intent without a run or text.
var ErrInvalidIntent = errors.New("invalid intent")

// Intent is what every agent write carries. TaskID is uuid.Nil when the
// run has no shared task.
type Intent struct {
	RunID  uuid.UUID
	TaskID uuid.UUID
	Text   string
}

func (in Intent) validate() error {
	if in.RunID == uuid.Nil || in.Text == "" {
		return fmt.Errorf("%w: run id and text are required", ErrInvalidIntent)
	}
	return nil
}

// nullUUID maps uuid.Nil to SQL NULL.
func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

// StartRun records a run and a RUN_STARTED ledger row.
func StartRun(ctx context.Context, q Querier, in Intent) error {
	if err := in.validate(); err != nil {
		return err
	}
	return execCall(ctx, q, sq.Expr("basalt_meta.start_run(?::uuid, ?::uuid, ?)",
		in.RunID.String(), nullUUID(in.TaskID), in.Text))
}

// BeginGuarded sets the session variables of an agent write on tx,
// transaction-local (set_config(..., true)), so nothing outlives the
// transaction on a pooled connection. Call it first in the transaction.
func BeginGuarded(ctx context.Context, tx pgx.Tx, in Intent) error {
	if err := in.validate(); err != nil {
		return err
	}
	task := ""
	if in.TaskID != uuid.Nil {
		task = in.TaskID.String()
	}
	return execCall(ctx, tx, sq.Expr(
		"set_config('basalt.intent', ?, true), set_config('basalt.run_id', ?, true), "+
			"set_config('basalt.task_id', ?, true), set_config('basalt.mode', ?, true)",
		in.Text, in.RunID.String(), task, ModeApply))
}

// Finish describes the statement that just ran in a guarded transaction.
// Op is used only when no row was touched (the guard opened no change).
type Finish struct {
	Op        string
	Statement string
	Params    []any
	Duration  time.Duration
}

// FinishChange stamps the statement, parameters and duration on the change
// the guard opened in tx, or records a zero-row change, chains a CHANGE
// ledger row, and returns the change id. Call it after the statement and
// before COMMIT.
func FinishChange(ctx context.Context, tx pgx.Tx, f Finish) (uuid.UUID, error) {
	params, err := paramsJSON(f.Params)
	if err != nil {
		return uuid.Nil, err
	}
	return returnUUID(ctx, tx, sq.Expr("basalt_meta.finish_change(?, ?, nullif(?::jsonb, 'null'), ?::int)",
		f.Op, f.Statement, params, f.Duration.Milliseconds()))
}

// Refusal is an action the engine or the guard refused.
type Refusal struct {
	Intent    Intent
	Op        string // SELECT, INSERT, UPDATE, DELETE or OTHER
	Statement string
	Params    []any
	Code      string
	Reason    string
	Duration  time.Duration
}

// RecordRefusal writes a REFUSED change record and ledger row. Call it in a
// new transaction (or autocommit) after the refused one rolled back.
func RecordRefusal(ctx context.Context, q Querier, r Refusal) (uuid.UUID, error) {
	params, err := paramsJSON(r.Params)
	if err != nil {
		return uuid.Nil, err
	}
	return returnUUID(ctx, q, sq.Expr(
		"basalt_meta.record_refusal(?::uuid, ?::uuid, ?, ?, ?, nullif(?::jsonb, 'null'), ?, ?, ?::int)",
		nullUUID(r.Intent.RunID), nullUUID(r.Intent.TaskID), r.Intent.Text, r.Op, r.Statement, params,
		r.Code, r.Reason, r.Duration.Milliseconds()))
}

// EventKind is an engine event record_event accepts.
type EventKind string

// Engine events (CONTRACT.md, basalt_meta functions).
const (
	// EventHeartbeat: the engine checked in (every hour).
	EventHeartbeat EventKind = "HEARTBEAT"
	// EventDeadMan: the engine checked in after more than 7 days of
	// silence (D14).
	EventDeadMan EventKind = "DEAD_MAN"
	// EventUncoveredTables: the set of unguarded tables changed.
	EventUncoveredTables EventKind = "UNCOVERED_TABLES"
)

// RecordEvent appends an engine event to the ledger, outside any run.
func RecordEvent(ctx context.Context, q Querier, kind EventKind, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return execCall(ctx, q, sq.Expr("basalt_meta.record_event(?, NULL, ?::jsonb)", string(kind), string(b)))
}

// Heartbeat records a HEARTBEAT ledger row (dead-man switch, D14).
func Heartbeat(ctx context.Context, q Querier, detail map[string]any) error {
	return RecordEvent(ctx, q, EventHeartbeat, detail)
}

// paramsJSON encodes statement parameters as a JSON array; nil params
// encode as JSON null, stored as SQL NULL.
func paramsJSON(params []any) (string, error) {
	b, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("params: %w", err)
	}
	return string(b), nil
}

// execCall runs SELECT <call> and discards the result.
func execCall(ctx context.Context, q Querier, call sq.Sqlizer) error {
	sql, args, err := psql.Select().Column(call).ToSql()
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, sql, args...)
	return err
}

func returnUUID(ctx context.Context, q Querier, call sq.Sqlizer) (uuid.UUID, error) {
	sql, args, err := psql.Select().Column(call).ToSql()
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = q.QueryRow(ctx, sql, args...).Scan(&id)
	return id, err
}
