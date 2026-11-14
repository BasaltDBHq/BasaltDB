package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// RevertScope is an agent's own proposal of what a revert covers: one of
// its changes, one of its runs, or its own changes in a task it ran in,
// optionally narrowed to some of its runs in that task and some tables
// (CONTRACT.md, Revert, The scope descriptor). The guard builds the
// descriptor with agents = [the calling role] and refuses anything outside
// the caller's own work (BS011 SCOPE_REFUSED).
type RevertScope struct {
	Kind revert.Scope
	ID   uuid.UUID
	// Runs narrows a TASK to some of the caller's runs in it; nil for all.
	Runs []uuid.UUID
	// Tables narrows the lines to some schema.table names; nil for all.
	Tables []string
}

// ownSelect is the SQL expression of the calling role's own descriptor for
// $1 (scope), $2 (scope id), $3 (runs) and $4 (tables), with agents
// = [session_user]: the role is the one Postgres authenticated, never an
// argument.
const ownSelect = `jsonb_build_object('scope', $1::text, 'scopeId', $2::text, ` +
	`'agents', jsonb_build_array(session_user::text), 'runs', $3::jsonb, 'tables', $4::jsonb)`

// args are the ownSelect arguments of s. A nil list is JSON null (all).
func (s RevertScope) args() ([]any, error) {
	runs, err := json.Marshal(s.Runs)
	if err != nil {
		return nil, err
	}
	tables, err := json.Marshal(s.Tables)
	if err != nil {
		return nil, err
	}
	return []any{string(s.Kind), s.ID.String(), string(runs), string(tables)}, nil
}

// PreviewRevert returns the revert lines of the caller's own scope as
// Postgres builds them (CONTRACT.md, Revert), in COLLATE "C" order,
// redacted for the caller. It changes nothing.
func PreviewRevert(ctx context.Context, q Querier, s RevertScope) ([]string, error) {
	args, err := s.args()
	if err != nil {
		return nil, err
	}
	// Plain SQL: a set-returning function in FROM over a built descriptor.
	rows, err := q.Query(ctx, `SELECT l FROM basalt_meta.preview_revert(`+ownSelect+`) AS l`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// PreviewPage is one page of a preview as an agent reads it (preview_revert):
// the totals of the whole preview and the page's lines, with values too
// large for the agent left out (CONTRACT.md, Large values).
type PreviewPage struct {
	// Lines and Restore count every line of the preview, and
	// AllAlreadyReverted says whether every one is a SKIP of a row a revert
	// of the scope already restored.
	Lines              int
	Restore            int
	AllAlreadyReverted bool
	// CursorFound is false when a cursor was given and no line of the
	// preview has its hash: the rows changed between pages.
	CursorFound bool
	// Page are the lines after the cursor, at most the limit, each with the
	// hash of its full signed text (the next cursor); More says another
	// page follows.
	Page []PreviewLine
	More bool
}

// PreviewLine is one line of a PreviewPage: its text with large values
// left out, and the SHA-256 (lowercase hex) of the full text.
type PreviewLine struct {
	Text string
	Hash string
}

// PreviewRevertPage previews the caller's own scope s as PreviewRevert does,
// and reads only the totals and the limit lines after the line whose hash
// is after ("" for the first page). Postgres counts, hashes and elides,
// so a large preview or value never crosses the wire on an agent's call.
func PreviewRevertPage(ctx context.Context, q Querier, s RevertScope, after string, limit int) (PreviewPage, error) {
	args, err := s.args()
	if err != nil {
		return PreviewPage{}, err
	}
	// Plain SQL: a set-returning function over a built descriptor, under a
	// recursive CTE (largevalue.ElideLines).
	sql := largevalue.With + `pv_all AS MATERIALIZED (
			SELECT p.n, p.t, ` + largevalue.SHA256Of("p.t") + ` AS hash, p.t::jsonb AS j
			FROM basalt_meta.preview_revert(` + ownSelect + `) WITH ORDINALITY AS p(t, n)
		), pv_tot AS MATERIALIZED (
			SELECT count(n) AS lines, count(n) FILTER (WHERE j->>'action' = 'RESTORE') AS restore,
				coalesce(bool_and(coalesce(j->>'conflict', '') = 'ALREADY_REVERTED'), false) AS reverted
			FROM pv_all
		), pv_cur AS MATERIALIZED (
			SELECT min(n) AS n FROM pv_all WHERE $5 <> '' AND hash = $5
		), pv_page AS MATERIALIZED (
			SELECT n, hash, j FROM pv_all WHERE n > coalesce((SELECT n FROM pv_cur), 0) ORDER BY n LIMIT $6
		), ` + largevalue.ElideLines(`SELECT n AS item, j AS line FROM pv_page`) + `
		SELECT t.lines, t.restore, t.reverted, $5 = '' OR (SELECT n FROM pv_cur) IS NOT NULL, p.hash, l.line::text
		FROM pv_tot t
		LEFT JOIN (pv_page p JOIN lv_lines l ON l.item = p.n) ON true
		ORDER BY p.n`
	rows, err := q.Query(ctx, sql, append(args, after, limit+1)...)
	if err != nil {
		return PreviewPage{}, err
	}
	defer rows.Close()
	var out PreviewPage
	for rows.Next() {
		var hash, text *string
		if err := rows.Scan(&out.Lines, &out.Restore, &out.AllAlreadyReverted, &out.CursorFound, &hash, &text); err != nil {
			return PreviewPage{}, err
		}
		if text != nil {
			out.Page = append(out.Page, PreviewLine{Text: *text, Hash: *hash})
		}
	}
	if err := rows.Err(); err != nil {
		return PreviewPage{}, err
	}
	if len(out.Page) > limit {
		out.Page, out.More = out.Page[:limit], true
	}
	return out, nil
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

// PrepareRevert stores the caller's own proposal s for the person to sign
// (basalt_meta.prepare_revert): Postgres runs it on trial, builds the lines
// and the binding, and appends REVERT_PENDING. A TASK the caller ran in
// with no line of its own is stored as an empty proposal (Rows 0) the
// person may widen on the page; it cannot be signed as it is. Over revert.MaxLines lines
// it stores a batched plan. Call it outside a read-only transaction; a
// large plan's trial can take minutes.
func PrepareRevert(ctx context.Context, q Querier, s RevertScope, intent string) (PreparedRevert, error) {
	args, err := s.args()
	if err != nil {
		return PreparedRevert{}, err
	}
	var p PreparedRevert
	// Plain SQL: a set-returning function in FROM over a built descriptor.
	err = q.QueryRow(ctx, `SELECT r.revert_id, r.binding_text, r.expires_at, r.lines
		FROM basalt_meta.prepare_revert(`+ownSelect+`, $5) AS r`, append(args, intent)...).
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
