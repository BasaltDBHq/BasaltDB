package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// errPreviewRollback ends a preview transaction: a preview never commits.
var errPreviewRollback = errors.New("preview rolled back")

// previewRaw is Preview before MapError.
func (s *Store) previewRaw(ctx context.Context, in action.Intent, sql string, params []any, assigned []string) ([]string, error) {
	var lines []string
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.BeginPreview(ctx, tx, guardIntent(in), s.limits.StatementTimeout); err != nil {
			return err
		}
		if _, _, _, err := runText(ctx, tx, sql, params, s.limits.ReadRowLimit, 0); err != nil {
			return err
		}
		// The lines go back to Postgres with the hold and never to the
		// agent: they are not charged to the call's budget, so a held
		// DELETE of a row with a large value is held, not refused
		// (CONTRACT.md, Large values, rule 6).
		var err error
		lines, err = guard.PreviewLines(budget.Without(ctx), tx, assigned)
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

// openRevealRaw is OpenReveal before MapError.
func (s *Store) openRevealRaw(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) ([]byte, error) {
	return guard.OpenReveal(ctx, s.db, id, proof, key)
}

// revealPreviewRaw is RevealPreview before MapError.
func (s *Store) revealPreviewRaw(ctx context.Context, in action.Intent, op action.Op, sql string, params []any,
	id uuid.UUID, ticket []byte,
) ([]approval.RevealedRow, error) {
	var rows []approval.RevealedRow
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.BeginPreview(ctx, tx, guardIntent(in), s.limits.StatementTimeout); err != nil {
			return err
		}
		if _, _, _, err := runText(ctx, tx, sql, params, s.limits.ReadRowLimit, 0); err != nil {
			return err
		}
		if _, err := guard.FinishChange(ctx, tx, guard.Finish{Op: string(op), Statement: sql, Params: params}); err != nil {
			return err
		}
		var err error
		if rows, err = guard.RevealApprovalRows(ctx, tx, id, ticket); err != nil {
			return err
		}
		return errPreviewRollback
	})
	if !errors.Is(err, errPreviewRollback) {
		return nil, err
	}
	return rows, nil
}

// holdRaw is Hold before MapError.
func (s *Store) holdRaw(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error) {
	h, err := guard.Hold(ctx, s.db, guardIntent(in), s.limits.StatementTimeout, guard.HoldRequest(r))
	return action.Held(h), err
}

// tableColumnsRaw is TableColumns before MapError.
func (s *Store) tableColumnsRaw(ctx context.Context, table string) ([]string, error) {
	// Plain SQL: a catalog query on to_regclass.
	rows, err := s.db.Query(ctx, `SELECT a.attname::text FROM pg_catalog.pg_attribute a
		WHERE a.attrelid = pg_catalog.to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
		ORDER BY a.attnum`, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// submitApprovalRaw is SubmitApproval before MapError.
func (s *Store) submitApprovalRaw(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	return guard.SubmitApproval(ctx, s.db, id, a)
}

// findApprovalRaw is FindApproval before MapError.
func (s *Store) findApprovalRaw(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	return ledger.FindApproval(ctx, s.db, id)
}

// listApprovalsRaw is ListApprovals before MapError.
func (s *Store) listApprovalsRaw(ctx context.Context, p action.ApprovalListParams) (pagination.Page[action.Approval], error) {
	return ledger.ListOpenApprovals(ctx, s.db, p)
}

// listOpenRevertsRaw is ListOpenReverts before MapError.
func (s *Store) listOpenRevertsRaw(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return ledger.ListOpenReverts(ctx, s.db, p)
}

// passkeysRaw is Passkeys before MapError.
func (s *Store) passkeysRaw(ctx context.Context) ([]passkey.Credential, error) {
	return ledger.Passkeys(ctx, s.db)
}
