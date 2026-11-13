package agentdb

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// errPreviewRollback ends a preview transaction: a preview never commits.
var errPreviewRollback = errors.New("preview rolled back")

// Preview runs a held write in a preview transaction (basalt.mode =
// PREVIEW) on the agent's credential and returns its preview lines; the
// transaction always rolls back. assigned names the columns whose new
// values the approval binds.
func (s *Store) Preview(ctx context.Context, in guard.Intent, sql string, params []any, assigned []string) ([]string, error) {
	var lines []string
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		if err := guard.BeginPreview(ctx, tx, in); err != nil {
			return err
		}
		if _, _, _, err := runText(ctx, tx, sql, params, s.limits.ReadRowLimit, 0); err != nil {
			return err
		}
		var err error
		lines, err = guard.PreviewLines(ctx, tx, assigned)
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

// Hold stores a held write for the person's approval.
func (s *Store) Hold(ctx context.Context, in guard.Intent, r guard.HoldRequest) (guard.Held, error) {
	return guard.Hold(ctx, s.db, in, r)
}

// TableColumns returns the columns an INSERT without a column list assigns:
// every non-generated column of table, in order, resolved as the agent's
// session would.
func (s *Store) TableColumns(ctx context.Context, table string) ([]string, error) {
	// Plain SQL: a catalog query on to_regclass.
	rows, err := s.db.Query(ctx, `SELECT a.attname::text FROM pg_catalog.pg_attribute a
		WHERE a.attrelid = pg_catalog.to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
		ORDER BY a.attnum`, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SubmitApproval relays the person's signed approval to Postgres.
func (s *Store) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	return guard.SubmitApproval(ctx, s.db, id, a)
}

// FindApproval returns one of the agent's approvals.
func (s *Store) FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	return ledger.FindApproval(ctx, s.db, id)
}

// ListApprovals returns one page of the agent's open approvals.
func (s *Store) ListApprovals(ctx context.Context, p ledger.ApprovalListParams) (pagination.Page[ledger.Approval], error) {
	return ledger.ListOpenApprovals(ctx, s.db, p)
}

// ListOpenReverts returns one page of the agent's reverts waiting for the
// person's signature or for its batches (ledger.ListOpenReverts).
func (s *Store) ListOpenReverts(ctx context.Context, p ledger.RevertListParams) (pagination.Page[ledger.Revert], error) {
	return ledger.ListOpenReverts(ctx, s.db, p)
}

// Passkeys returns the registered passkeys' public data.
func (s *Store) Passkeys(ctx context.Context) ([]passkey.Credential, error) {
	return ledger.Passkeys(ctx, s.db)
}
