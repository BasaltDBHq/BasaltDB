package guard

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// RegisterPasskey stores the person's passkey (basalt init, admin
// credential) with its user handle when known. Re-registering a credential
// replaces its key and resets its counter; a revoked one is refused.
func RegisterPasskey(ctx context.Context, q Querier, cred passkey.Credential, label string) error {
	x, y, err := cred.XY()
	if err != nil {
		return err
	}
	var handle any // NULL when unknown
	if len(cred.UserHandle) > 0 {
		handle = cred.UserHandle
	}
	return execCall(ctx, q, sq.Expr("basalt_meta.register_passkey(?::bytea, ?::bytea, ?::bytea, ?, ?, ?, ?::bytea)",
		cred.ID, x, y, cred.Relying.RPID, cred.Relying.Origin, label, handle))
}

// BeginPreview sets the session variables of a preview on tx: the guard
// records the rows as usual and refuses any commit (PREVIEW_CANNOT_COMMIT).
// Roll tx back after reading PreviewLines.
func BeginPreview(ctx context.Context, tx pgx.Tx, in Intent, timeout time.Duration) error {
	if err := BeginGuarded(ctx, tx, in, timeout); err != nil {
		return err
	}
	return execCall(ctx, tx, sq.Expr("set_config('basalt.mode', ?, true)", ModePreview))
}

// BeginApproved sets the session variables of a write applied under a
// signed approval on tx.
func BeginApproved(ctx context.Context, tx pgx.Tx, in Intent, timeout time.Duration, approvalID uuid.UUID) error {
	if err := BeginGuarded(ctx, tx, in, timeout); err != nil {
		return err
	}
	return execCall(ctx, tx, sq.Expr("set_config('basalt.approval_id', ?, true)", approvalID.String()))
}

// PreviewLines returns the preview lines of the statement just run in a
// preview transaction (CONTRACT.md, Approvals), in order. assigned names
// the columns whose new values the approval binds.
func PreviewLines(ctx context.Context, tx pgx.Tx, assigned []string) ([]string, error) {
	if assigned == nil {
		assigned = []string{}
	}
	// Plain SQL: a set-returning function in FROM.
	rows, err := tx.Query(ctx, "SELECT l FROM basalt_meta.preview_lines($1::text[]) AS l", assigned)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// HoldRequest is a write to hold for the person's approval. Verb is the
// statement's own command (INSERT, UPDATE or DELETE), the verb of its
// APPROVAL_PENDING ledger row; empty derives it from the first line's op.
type HoldRequest struct {
	Verb      string
	Statement string
	Params    []any
	Assigned  []string
	Lines     []string
}

// Held is a stored held write.
type Held struct {
	ApprovalID  uuid.UUID
	BindingText string
	ExpiresAt   time.Time
}

// Hold stores a held write and its APPROVAL_PENDING change in its own
// transaction, with the intent's session variables and timeout set
// (BeginGuarded).
func Hold(ctx context.Context, db TxBeginner, in Intent, timeout time.Duration, r HoldRequest) (Held, error) {
	params, err := paramsJSON(r.Params)
	if err != nil {
		return Held{}, err
	}
	assigned := r.Assigned
	if assigned == nil {
		assigned = []string{}
	}
	var h Held
	err = pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := BeginGuarded(ctx, tx, in, timeout); err != nil {
			return err
		}
		// Plain SQL: a set-returning function in FROM.
		return tx.QueryRow(ctx, `SELECT h.approval_id, h.binding_text, h.expires_at
			FROM basalt_meta.hold_action(nullif($1, ''), $2, nullif($3::jsonb, 'null'), $4::text[], $5::text[]) AS h`,
			r.Verb, r.Statement, params, assigned, r.Lines).Scan(&h.ApprovalID, &h.BindingText, &h.ExpiresAt)
	})
	if err != nil {
		return Held{}, err
	}
	return h, nil
}

// TxBeginner starts transactions (a pgx pool, connection or the engine's DB).
type TxBeginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// SubmitApproval relays the person's passkey assertion for an approval;
// Postgres verifies it. It returns when the approval was recorded.
func SubmitApproval(ctx context.Context, q Querier, approvalID uuid.UUID, a passkey.Assertion) (time.Time, error) {
	sql, args, err := psql.Select().Column(sq.Expr(
		"basalt_meta.submit_approval(?::uuid, ?::bytea, ?::bytea, ?::bytea, ?::bytea)",
		approvalID.String(), a.CredentialID, a.AuthenticatorData, a.ClientDataJSON, a.Signature)).ToSql()
	if err != nil {
		return time.Time{}, fmt.Errorf("submit approval: %w", err)
	}
	var at time.Time
	err = q.QueryRow(ctx, sql, args...).Scan(&at)
	return at, err
}
