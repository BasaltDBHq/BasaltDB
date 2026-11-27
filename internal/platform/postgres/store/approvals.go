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
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
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
func (s *Store) revealHeldRaw(ctx context.Context, id uuid.UUID, run approvalstore.HeldRun,
	proof passkey.Assertion, key []byte,
) ([]approval.RevealedRow, error) {
	held, err := heldStatement(run.Request)
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
		if err := guard.BeginPreview(ctx, tx, guardIntent(run.Intent), s.limits.StatementTimeout); err != nil {
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
// parameters, numbers kept exact as the write tool decodes them. A request
// of any other family is refused before the policy reads its text.
func heldStatement(req approval.HeldRequest) (revealRun, error) {
	if req.Kind != approval.RequestSQL {
		return revealRun{}, fmt.Errorf("the held request is of family %q, not SQL", req.Kind)
	}
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

// holdRaw is Hold before MapError. The guard's verb is Basalt's op: for
// the three ops a write is held for (INSERT, UPDATE, DELETE) the word is
// the same.
func (s *Store) holdRaw(ctx context.Context, in action.Intent, r approvalstore.HoldRequest) (approvalstore.Held, error) {
	h, err := guard.Hold(ctx, s.db, guardIntent(in), s.limits.StatementTimeout, guard.HoldRequest{
		Verb: string(r.Op), Statement: r.Request.Text, Params: r.Request.Params, Assigned: r.Assigned, Lines: r.Lines,
	})
	return approvalstore.Held(h), err
}

// tableColumnsRaw is TableColumns before MapError.
func (s *Store) tableColumnsRaw(ctx context.Context, table string) ([]sqlguard.Column, error) {
	// Plain SQL: a catalog query on to_regclass.
	rows, err := s.db.Query(ctx, `SELECT a.attname::text,
		       coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), ''), a.attidentity <> '', a.attgenerated <> ''
		  FROM pg_catalog.pg_attribute a
		  LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		 WHERE a.attrelid = pg_catalog.to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped
		 ORDER BY a.attnum`, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (sqlguard.Column, error) {
		var c sqlguard.Column
		err := row.Scan(&c.Name, &c.Default, &c.Identity, &c.Generated)
		return c, err
	})
}

// fixedTimes runs eval, the SELECT sqlguard.PlanTimes made of a held
// write's time functions, once, and returns each value as text in ISO form
// with its zone offset where the type has one, which Postgres reads back
// the same whatever the session's DateStyle. The read-only transaction
// sets DateStyle for itself only.
func (s *Store) fixedTimes(ctx context.Context, eval string) ([]string, error) {
	var values []string
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL datestyle = 'ISO, YMD'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, eval)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return errors.New("fixing the times returned no row")
		}
		raw := rows.RawValues()
		values = make([]string, len(raw))
		for i, v := range raw {
			if v == nil {
				return errors.New("a fixed time is NULL")
			}
			values[i] = string(v)
		}
		rows.Close()
		return rows.Err()
	})
	return values, MapError(err)
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
func (s *Store) listApprovalsRaw(ctx context.Context, p approvalstore.ApprovalListParams) (pagination.Page[action.Approval], error) {
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
// refusals (approvalstore.ApprovalRefusalError) after MapError, per call. An
// answer no mapping names is returned as MapError made it. MapError's
// approvalDetails are not reused here: they serve the agent's apply, and
// their NOT_THIS_AGENT also covers "another agent", which a reveal answers
// as signed or used meanwhile.

// approvalRefusal is err refused for reason, with the store's text detail.
func approvalRefusal(err error, reason approvalstore.ApprovalReason, detail string) error {
	return &approvalstore.ApprovalRefusalError{Reason: reason, Detail: detail, Err: err}
}

// findApprovalRefusal maps FindApproval's error: an approval the role does
// not hold is ApprovalNotFound.
func findApprovalRefusal(err error) error {
	if errors.Is(err, ledger.ErrApprovalNotFound) {
		return approvalRefusal(err, approvalstore.ApprovalNotFound, "")
	}
	return err
}

// revealApprovalRefusal maps RevealHeld's errors: an APPROVAL_INVALID
// whose detail is a failed reveal proof, rows changed since the hold, or
// an approval the role does not hold (NO_SUCH_APPROVAL, the hint the
// sentence), compared for equality in this order;
// any other APPROVAL_INVALID is an approval signed or used meanwhile.
func revealApprovalRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil || guard.Code(se.LedgerCode) != guard.CodeApprovalInvalid {
		return err
	}
	switch se.Detail {
	case guard.RevealRefused:
		return approvalRefusal(err, approvalstore.ApprovalRevealRefused, se.Detail)
	case guard.RevealRowsChanged:
		return approvalRefusal(err, approvalstore.ApprovalRevealRowsChanged, se.Detail)
	case guard.NoSuchApproval:
		return approvalRefusal(err, approvalstore.ApprovalNotFound, se.Hint)
	}
	return approvalRefusal(err, approvalstore.ApprovalNotOpen, se.Detail)
}

// pluginApprovalRefusal maps SubmitPluginApproval's errors to the plugin's
// typed refusals (pluginmodel.ApprovalRefusalError): APPROVAL_EXPIRED is
// an expired approval; an APPROVAL_INVALID whose detail is an approval
// already signed, cancelled or not held is that, and any other is a
// revoked or unknown passkey (the catalog's PASSKEY_REVOKED) or a
// signature the guard did not accept. Any other answer is returned as
// MapError made it.
func pluginApprovalRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil {
		return err
	}
	reason := pluginmodel.ApprovalBadSignature
	switch guard.Code(se.LedgerCode) {
	case guard.CodeApprovalExpired:
		reason = pluginmodel.ApprovalExpired
	case guard.CodeApprovalInvalid:
		switch {
		case se.Detail == guard.DetailAlreadyApproved:
			reason = pluginmodel.ApprovalAlreadyApproved
		case se.Detail == guard.DetailApprovalCancelled:
			reason = pluginmodel.ApprovalCancelled
		case se.Detail == guard.Withdrawn:
			reason = pluginmodel.ApprovalWithdrawn
		case se.Detail == guard.DetailApprovalNotFound:
			reason = pluginmodel.ApprovalNotFound
		case se.Reason == action.ReasonPasskeyRevoked:
			reason = pluginmodel.ApprovalPasskeyRevoked
		}
	default:
		return err
	}
	return &pluginmodel.ApprovalRefusalError{Reason: reason, Err: err}
}
