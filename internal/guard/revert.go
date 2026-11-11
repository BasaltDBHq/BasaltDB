package guard

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// RevertScope is what a revert covers: one change, one run, or one task
// across agents (CONTRACT.md, Revert).
type RevertScope struct {
	Kind revert.Scope
	ID   uuid.UUID
}

// PreviewRevert returns the revert lines of scope as Postgres builds them
// (CONTRACT.md, Revert), in COLLATE "C" order, redacted for the caller.
// It changes nothing.
func PreviewRevert(ctx context.Context, q Querier, s RevertScope) ([]string, error) {
	// Plain SQL: a set-returning function in FROM.
	rows, err := q.Query(ctx, `SELECT l FROM basalt_meta.preview_revert($1, $2::uuid) AS l`, string(s.Kind), s.ID.String())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// PreparedRevert is a revert stored for the person to sign. Lines are every
// line of a one-call revert, or the sample of a batched plan (Batched).
type PreparedRevert struct {
	RevertID    uuid.UUID
	BindingText string
	ExpiresAt   time.Time
	Lines       []string
	Batched     bool
}

// PrepareRevert stores a revert of scope for the person to sign
// (basalt_meta.prepare_revert): Postgres runs it on trial, builds the lines
// and the binding, and appends REVERT_PENDING. Over revert.MaxLines lines
// it stores a batched plan. Call it outside a read-only transaction; a
// large plan's trial can take minutes.
func PrepareRevert(ctx context.Context, q Querier, s RevertScope, intent string) (PreparedRevert, error) {
	var p PreparedRevert
	// Plain SQL: a set-returning function in FROM.
	err := q.QueryRow(ctx, `SELECT r.revert_id, r.binding_text, r.expires_at, r.lines
		FROM basalt_meta.prepare_revert($1, $2::uuid, $3) AS r`, string(s.Kind), s.ID.String(), intent).
		Scan(&p.RevertID, &p.BindingText, &p.ExpiresAt, &p.Lines)
	if err != nil {
		return PreparedRevert{}, err
	}
	b, err := revert.ParseBinding(p.BindingText)
	if err != nil {
		return PreparedRevert{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	p.Batched = b.Batched
	return p, nil
}

// Prepare time limits (agent-assisted revert design, Preparing). The
// person's CLI may take minutes on a large scope; an MCP call stays under
// the 2 minutes after which Claude Code moves a tool call to the
// background.
const (
	CLIPrepareTimeout = 10 * time.Minute
	MCPPrepareTimeout = 100 * time.Second
)

// ErrPrepareTimeout is a timeout shorter than the millisecond
// statement_timeout counts in, where 0 would mean no limit at all.
var ErrPrepareTimeout = errors.New("guard: a prepare timeout must be at least 1 ms")

// PrepareRevertWithin prepares a revert of scope in its own transaction on
// db, with statement_timeout set to timeout for that transaction only
// (set_config(..., true)), whatever the role's default is. Past it
// Postgres cancels the prepare (SQLSTATE 57014) and nothing is stored.
// basalt revert and the engine's request_revert both prepare through it.
func PrepareRevertWithin(ctx context.Context, db TxBeginner, s RevertScope, intent string, timeout time.Duration) (PreparedRevert, error) {
	if timeout < time.Millisecond {
		return PreparedRevert{}, ErrPrepareTimeout
	}
	sql, args, err := psql.Select().
		Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", strconv.FormatInt(timeout.Milliseconds(), 10))).
		ToSql()
	if err != nil {
		return PreparedRevert{}, err
	}
	var p PreparedRevert
	err = pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		var err error
		p, err = PrepareRevert(ctx, tx, s, intent)
		return err
	})
	if err != nil {
		return PreparedRevert{}, err
	}
	return p, nil
}

// AppliedRevert is the result of apply_revert: for a one-call revert its
// change record, the rows it restored and the rows it skipped; for a
// batched plan the signature only (Rows 0), the lines still to apply and
// the time they must be applied by.
type AppliedRevert struct {
	ChangeID uuid.UUID  `json:"changeId"`
	Rows     int        `json:"rows"`
	Skipped  int        `json:"skipped"`
	Batched  bool       `json:"batched,omitempty"`
	Pending  int        `json:"pending,omitempty"`
	ApplyBy  *time.Time `json:"applyBy,omitempty"`
}

// ApplyRevert relays the person's passkey assertion for a prepared revert
// (basalt_meta.apply_revert). Postgres verifies it and, for a one-call
// revert, runs the revert in the same call; any row that changed since the
// preview refuses the whole revert with REVERT_INVALID. For a batched plan
// it records the signature and the agent then applies the plan with
// ApplyRevertBatch. Run it in its own transaction.
func ApplyRevert(ctx context.Context, q Querier, revertID uuid.UUID, a passkey.Assertion) (AppliedRevert, error) {
	var out AppliedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.apply_revert($1::uuid, $2::bytea, $3::bytea, $4::bytea, $5::bytea)`,
		revertID.String(), a.CredentialID, a.AuthenticatorData, a.ClientDataJSON, a.Signature).
		Scan(&out)
	if err != nil {
		return AppliedRevert{}, err
	}
	return out, nil
}

// Outcomes of a batched plan's lines (CONTRACT.md, Revert, Large plans).
const (
	OutcomePending  = "PENDING"
	OutcomeRestored = "RESTORED"
	OutcomeSkipped  = "SKIPPED"
)

// BatchItem is what one batch did with one line of the plan.
type BatchItem struct {
	Line     int    `json:"line"`
	Outcome  string `json:"outcome"`
	Conflict string `json:"conflict,omitempty"`
	SQLState string `json:"sqlState,omitempty"`
}

// BatchResult is one applied batch: its number, the plan's status and
// totals after it, and this batch's lines in the order given.
type BatchResult struct {
	RevertID uuid.UUID   `json:"revertId"`
	Batch    int         `json:"batch"`
	Status   string      `json:"status"`
	Restored int         `json:"restored"`
	Skipped  int         `json:"skipped"`
	Pending  int         `json:"pending"`
	Items    []BatchItem `json:"items"`
}

// ApplyRevertBatch applies lines of a signed batched plan
// (basalt_meta.apply_revert_batch), as the role that prepared it. Postgres
// refuses the whole batch unless every line is in the plan and pending,
// re-checks each line with its row locked, and skips (people win) a row
// changed since the plan was built. Run it in its own transaction.
func ApplyRevertBatch(ctx context.Context, q Querier, revertID uuid.UUID, lines []int) (BatchResult, error) {
	var out BatchResult
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.apply_revert_batch($1::uuid, $2::int[])`, revertID.String(), lines).Scan(&out)
	if err != nil {
		return BatchResult{}, err
	}
	return out, nil
}
