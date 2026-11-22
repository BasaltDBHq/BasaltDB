package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// previewRevertRaw is PreviewRevert before MapError.
func (s *Store) previewRevertRaw(ctx context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error) {
	var page action.PreviewPage
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		page, err = guard.PreviewRevertPage(ctx, tx, action.Scope(scope), after, limit)
		if err != nil {
			return err
		}
		return errPreviewRollback
	})
	if !errors.Is(err, errPreviewRollback) {
		return action.PreviewPage{}, err
	}
	return previewPageOf(page), nil
}

// prepareRevertRaw is PrepareRevert before MapError.
func (s *Store) prepareRevertRaw(ctx context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error) {
	var p action.PreparedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		p, err = guard.PrepareRevertWithin(ctx, savepoint{tx}, action.Scope(scope), intent, timeout)
		if err != nil {
			return err
		}
		if p.LineCount == 0 {
			return action.ErrEmptyProposal
		}
		return nil
	})
	if err != nil {
		return action.PreparedRevert{}, err
	}
	return action.PreparedRevert(p), nil
}

// rescopeRevertRaw is RescopeRevert before MapError.
func (s *Store) rescopeRevertRaw(ctx context.Context, req action.RescopeRequest, timeout time.Duration) (action.RescopedRevert, error) {
	var out action.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.RescopeRevert(ctx, tx, action.RescopeRequest(req))
		return err
	})
	return rescopedOf(out), err
}

// resetRevertRaw is ResetRevert before MapError.
func (s *Store) resetRevertRaw(ctx context.Context, id uuid.UUID, timeout time.Duration) (action.RescopedRevert, error) {
	var out action.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.ResetRevert(ctx, tx, id)
		return err
	})
	return rescopedOf(out), err
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

// hasChangeRaw is HasChange before MapError.
func (s *Store) hasChangeRaw(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.exists(ctx, "basalt_meta.agent_changes", sq.Eq{"change_id": id.String()})
}

// hasTaskRunRaw is HasTaskRun before MapError.
func (s *Store) hasTaskRunRaw(ctx context.Context, id uuid.UUID) (bool, error) {
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

// revertedByRaw is RevertedBy before MapError.
func (s *Store) revertedByRaw(ctx context.Context, scope action.Scope) (uuid.UUID, error) {
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

// findRevertRaw is FindRevert before MapError.
func (s *Store) findRevertRaw(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	return ledger.FindRevert(ctx, s.db, id)
}

// revertLinesRaw is RevertLines before MapError.
func (s *Store) revertLinesRaw(ctx context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	return ledger.ListRevertLinesMarked(ctx, s.db, p)
}

// applyRevertBatchRaw is ApplyRevertBatch before MapError.
func (s *Store) applyRevertBatchRaw(ctx context.Context, id uuid.UUID, lines []int) (action.BatchResult, error) {
	var out action.BatchResult
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		out, err = guard.ApplyRevertBatch(ctx, tx, id, lines)
		return err
	})
	return batchResultOf(out), err
}

// applyRevertRaw is ApplyRevert before MapError.
func (s *Store) applyRevertRaw(ctx context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error) {
	var out action.AppliedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.SetTimeouts(ctx, tx, s.limits.StatementTimeout); err != nil {
			return err
		}
		var err error
		out, err = guard.ApplyRevert(ctx, tx, id, a)
		return err
	})
	return action.AppliedRevert(out), err
}

// revertNonceRaw is RevertNonce before MapError.
func (s *Store) revertNonceRaw(ctx context.Context, id uuid.UUID) ([]byte, error) {
	return guard.RevertNonce(ctx, s.db, id)
}

// rejectRevertRaw is RejectRevert before MapError.
func (s *Store) rejectRevertRaw(ctx context.Context, id uuid.UUID, note string, token []byte) (action.RejectedRevert, error) {
	r, err := guard.RejectRevert(ctx, s.db, id, note, token)
	return action.RejectedRevert(r), err
}

// revealNonceRaw is RevealNonce before MapError.
func (s *Store) revealNonceRaw(ctx context.Context, kind string, id uuid.UUID) ([]byte, error) {
	return guard.RevealNonce(ctx, s.db, kind, id)
}

// revealRevertRowsRaw is RevealRevertRows before MapError.
func (s *Store) revealRevertRowsRaw(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) (action.RevealedRevert, error) {
	var out action.RevealedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		out, err = guard.RevealRevertRows(ctx, tx, id, proof, key)
		return err
	})
	return action.RevealedRevert(out), err
}
