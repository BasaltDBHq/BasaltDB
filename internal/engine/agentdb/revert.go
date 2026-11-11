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

// PrepareRevert stores a revert of scope for the person to sign
// (basalt_meta.prepare_revert) on the agent's credential, in its own
// transaction with the statement timeout set to timeout instead of the
// agent's limit, as basalt revert does.
func (s *Store) PrepareRevert(ctx context.Context, scope guard.RevertScope, intent string, timeout time.Duration) (guard.PreparedRevert, error) {
	return guard.PrepareRevertWithin(ctx, s.db, scope, intent, timeout)
}

// HasChange reports whether the agent's view of the change record shows
// change id: one of its own changes, or a revert's change that covered it.
func (s *Store) HasChange(ctx context.Context, id uuid.UUID) (bool, error) {
	q, args, err := psql.Select().
		Column(sq.Expr("EXISTS (?)", psql.Select("1").From("basalt_meta.agent_changes").Where(sq.Eq{"change_id": id.String()}))).
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
