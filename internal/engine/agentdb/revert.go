package agentdb

import (
	"context"
	"errors"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// PreviewRevert returns the revert lines of scope (basalt_meta
// preview_revert) on the agent's credential. The guard runs the revert on
// trial and undoes it; this transaction is read-write for that, and is
// rolled back anyway.
func (s *Store) PreviewRevert(ctx context.Context, scope guard.RevertScope) ([]string, error) {
	var lines []string
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		lines, err = guard.PreviewRevert(ctx, tx, scope)
		if err != nil {
			return err
		}
		return errPreviewRollback
	})
	if !errors.Is(err, errPreviewRollback) {
		return nil, err
	}
	return lines, nil
}

// ErrEmptyProposal is a task revert with no line of the agent's own. The
// guard stores such a proposal for the person to widen on the page (basalt
// revert --task); through MCP it is NOTHING_TO_REVERT (RS-6), so PrepareRevert
// rolls it back.
var ErrEmptyProposal = errors.New("the task has no line of this agent's own to revert")

// PrepareRevert stores a revert of scope for the person to sign
// (basalt_meta.prepare_revert) on the agent's credential, in its own
// transaction with the statement timeout set to timeout instead of the
// agent's limit, as basalt revert does. A proposal with no line is rolled
// back and answered ErrEmptyProposal.
func (s *Store) PrepareRevert(ctx context.Context, scope guard.RevertScope, intent string, timeout time.Duration) (guard.PreparedRevert, error) {
	var p guard.PreparedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		p, err = guard.PrepareRevertWithin(ctx, savepoint{tx}, scope, intent, timeout)
		if err != nil {
			return err
		}
		if len(p.Lines) == 0 {
			return ErrEmptyProposal
		}
		return nil
	})
	if err != nil {
		return guard.PreparedRevert{}, err
	}
	return p, nil
}

// RescopeRevert changes the scope of a revert the agent's role prepared
// (basalt_meta.rescope_revert), for the person on the revert page, in its
// own transaction with the statement timeout set to timeout instead of the
// agent's limit. Past it Postgres cancels the rescope (57014) and nothing
// changes.
func (s *Store) RescopeRevert(ctx context.Context, req guard.RescopeRequest, timeout time.Duration) (guard.RescopedRevert, error) {
	var out guard.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.RescopeRevert(ctx, tx, req)
		return err
	})
	return out, err
}

// ResetRevert puts a widened revert the agent's role prepared back to its
// proposal (basalt_meta.reset_revert), for the agent's reissueLink, under
// the same time limit as a rescope.
func (s *Store) ResetRevert(ctx context.Context, id uuid.UUID, timeout time.Duration) (guard.RescopedRevert, error) {
	var out guard.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.ResetRevert(ctx, tx, id)
		return err
	})
	return out, err
}

// setStatementTimeout sets statement_timeout for tx only.
func setStatementTimeout(ctx context.Context, tx pgx.Tx, timeout time.Duration) error {
	q, args, err := psql.Select().
		Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", strconv.FormatInt(timeout.Milliseconds(), 10))).
		ToSql()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, args...)
	return err
}

// savepoint begins a savepoint in tx where a guard helper begins a
// transaction, so its work commits or rolls back with tx.
type savepoint struct{ tx pgx.Tx }

func (s savepoint) BeginTx(ctx context.Context, _ pgx.TxOptions) (pgx.Tx, error) {
	return s.tx.Begin(ctx)
}

// HasChange reports whether the agent's view of the change record shows
// change id: one of its own changes, or a revert's change that covered it.
func (s *Store) HasChange(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.exists(ctx, "basalt_meta.agent_changes", sq.Eq{"change_id": id.String()})
}

// HasTaskRun reports whether the agent has a run with task id id, read
// through its agent_runs view (RS-1: a task the agent ran in is its own
// scope; any run with that task id counts).
func (s *Store) HasTaskRun(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.exists(ctx, "basalt_meta.agent_runs", sq.Eq{"task_id": id.String()})
}

// exists reports whether the agent's view from has a row matching where.
func (s *Store) exists(ctx context.Context, from string, where sq.Eq) (bool, error) {
	q, args, err := psql.Select().
		Column(sq.Expr("EXISTS (?)", psql.Select("1").From(from).Where(where))).
		ToSql()
	if err != nil {
		return false, err
	}
	var ok bool
	err = s.db.QueryRow(ctx, q, args...).Scan(&ok)
	return ok, err
}

// RevertedBy returns the change record of the latest revert that covered
// scope in the agent's view of the ledger, or uuid.Nil when none did. A change
// scope is the change itself; a run or task scope is any of its changes. The
// revert's change is what request_revert takes to redo the reverted work.
func (s *Store) RevertedBy(ctx context.Context, scope guard.RevertScope) (uuid.UUID, error) {
	column := map[revert.Scope]string{
		revert.ScopeChange: "c.change_id", revert.ScopeRun: "c.run_id", revert.ScopeTask: "c.task_id",
	}[scope.Kind]
	if column == "" {
		return uuid.Nil, nil
	}
	// Raw join: squirrel cannot express a lateral unnest of the array column.
	q, args, err := psql.Select("rb").
		From("basalt_meta.agent_changes c").
		CrossJoin("LATERAL unnest(c.reverted_by) rb").
		Where(sq.Eq{column: scope.ID.String()}).
		OrderBy("rb DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.db.QueryRow(ctx, q, args...).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// FindRevert returns a revert the agent's role prepared.
func (s *Store) FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	return ledger.FindRevert(ctx, s.db, id)
}

// RevertLines returns one page of a batched plan's lines.
func (s *Store) RevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	return ledger.ListRevertLines(ctx, s.db, p)
}

// ApplyRevertBatch applies lines of a signed plan in one transaction on the
// agent's credential (basalt_meta.apply_revert_batch), under the agent's
// statement timeout.
func (s *Store) ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (guard.BatchResult, error) {
	var out guard.BatchResult
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		out, err = guard.ApplyRevertBatch(ctx, tx, id, lines)
		return err
	})
	return out, err
}

// ApplyRevert relays the person's signed revert (basalt_meta.apply_revert)
// on the agent's credential, as basalt revert does: Postgres verifies the
// passkey assertion and runs the revert, or for a large plan records the
// signature.
func (s *Store) ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error) {
	return guard.ApplyRevert(ctx, s.db, id, a)
}

// RevertNonce reads the rescope nonce of a revert the agent's role prepared
// (basalt_meta.revert_nonce).
func (s *Store) RevertNonce(ctx context.Context, id uuid.UUID) ([]byte, error) {
	return guard.RevertNonce(ctx, s.db, id)
}

// RejectRevert marks a pending revert the agent's role prepared REJECTED
// for the person on the revert page (basalt_meta.reject_revert), with the
// scope token the engine holds for a widened revert's rotated link.
func (s *Store) RejectRevert(ctx context.Context, id uuid.UUID, note string, token []byte) (guard.RejectedRevert, error) {
	return guard.RejectRevert(ctx, s.db, id, note, token)
}
