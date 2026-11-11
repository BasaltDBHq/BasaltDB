package agentdb

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
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
