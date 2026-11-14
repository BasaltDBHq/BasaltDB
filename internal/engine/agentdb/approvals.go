package agentdb

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
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
		if err := guard.BeginPreview(ctx, tx, in, s.limits.StatementTimeout); err != nil {
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
		lines, err = guard.PreviewLines(resultsize.Unbudgeted(ctx), tx, assigned)
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

// OpenReveal checks the person's reveal proof for a held write and returns
// the ticket of the re-run preview (basalt_meta.open_reveal), in its own
// transaction. The caller keeps the ticket in memory for this one request.
func (s *Store) OpenReveal(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) ([]byte, error) {
	return guard.OpenReveal(ctx, s.db, id, proof, key)
}

// RevealPreview re-runs a held write in a preview transaction exactly as an
// apply runs it (the statement with its parameters, then finish_change, so
// the change records them), and reads the held approval's hidden rows with
// ticket (basalt_meta.reveal_approval_rows). The transaction always rolls
// back.
func (s *Store) RevealPreview(ctx context.Context, in guard.Intent, op sqlguard.Op, sql string, params []any,
	id uuid.UUID, ticket []byte,
) ([]approval.RevealedRow, error) {
	var rows []approval.RevealedRow
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.BeginPreview(ctx, tx, in, s.limits.StatementTimeout); err != nil {
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

// Hold stores a held write for the person's approval.
func (s *Store) Hold(ctx context.Context, in guard.Intent, r guard.HoldRequest) (guard.Held, error) {
	return guard.Hold(ctx, s.db, in, s.limits.StatementTimeout, r)
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
