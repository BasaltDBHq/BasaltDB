package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
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

// revealHeldRaw is RevealHeld before MapError.
func (s *Store) revealHeldRaw(ctx context.Context, id uuid.UUID, in action.Intent, req approval.HeldRequest,
	proof passkey.Assertion, key []byte,
) ([]approval.RevealedRow, error) {
	held, err := heldStatement(req)
	if err != nil {
		return nil, err
	}
	ticket, err := guard.OpenReveal(ctx, s.db, id, proof, key)
	if err != nil {
		return nil, err
	}
	defer clear(ticket)
	var rows []approval.RevealedRow
	err = pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.BeginPreview(ctx, tx, guardIntent(in), s.limits.StatementTimeout); err != nil {
			return err
		}
		if _, _, _, err := runText(ctx, tx, held.sql, held.params, s.limits.ReadRowLimit, 0); err != nil {
			return err
		}
		if _, err := guard.FinishChange(ctx, tx, guard.Finish{Op: string(held.op), Statement: held.sql, Params: held.params}); err != nil {
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

// revealRun is a held SQL request as it re-runs: its statement, the op the
// SQL policy reads from it and its parameters.
type revealRun struct {
	op     action.Op
	sql    string
	params []any
}

// heldStatement reads the held write from the binding's SQL request: its
// statement, checked again with the SQL policy for its op, and its
// parameters, numbers kept exact as the write tool decodes them.
func heldStatement(req approval.HeldRequest) (revealRun, error) {
	stmt, err := Check(req.Statement, action.ToolWrite)
	if err != nil {
		return revealRun{}, fmt.Errorf("the held statement no longer parses: %w", err)
	}
	params := make([]any, 0, len(req.Params))
	for _, raw := range req.Params {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return revealRun{}, fmt.Errorf("a held parameter: %w", err)
		}
		params = append(params, v)
	}
	return revealRun{op: stmt.Op, sql: req.Statement, params: params}, nil
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

// The guard's answers to an approval call, mapped to the approval's own
// refusals (action.ApprovalRefusalError) after MapError, per call. An
// answer no mapping names is returned as MapError made it. MapError's approvalDetails
// are not reused here: they serve the agent's apply, and their
// NOT_THIS_AGENT also covers "another agent", which a reveal answers as
// signed or used meanwhile.

// approvalNotFoundDetail is the guard's detail for an approval the calling
// role does not hold, or none.
const approvalNotFoundDetail = "no such approval"

// approvalRefusal is err refused for reason, with the store's text detail.
func approvalRefusal(err error, reason action.ApprovalReason, detail string) error {
	return &action.ApprovalRefusalError{Reason: reason, Detail: detail, Err: err}
}

// findApprovalRefusal maps FindApproval's error: an approval the role does
// not hold is ApprovalNotFound.
func findApprovalRefusal(err error) error {
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return approvalRefusal(err, action.ApprovalNotFound, "")
	}
	return err
}

// revealApprovalRefusal maps RevealHeld's errors: an APPROVAL_INVALID
// whose detail is a failed reveal proof, rows changed since the hold, or
// an approval the role does not hold, compared for equality in this order;
// any other APPROVAL_INVALID is an approval signed or used meanwhile.
func revealApprovalRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil || guardmodel.Code(se.LedgerCode) != guardmodel.CodeApprovalInvalid {
		return err
	}
	switch se.Detail {
	case guardmodel.RevealRefused:
		return approvalRefusal(err, action.ApprovalRevealRefused, se.Detail)
	case guardmodel.RevealRowsChanged:
		return approvalRefusal(err, action.ApprovalRevealRowsChanged, se.Detail)
	case approvalNotFoundDetail:
		return approvalRefusal(err, action.ApprovalNotFound, se.Detail)
	}
	return approvalRefusal(err, action.ApprovalNotOpen, se.Detail)
}
