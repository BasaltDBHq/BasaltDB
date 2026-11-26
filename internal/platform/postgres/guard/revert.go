package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pglargevalue"
)

// ownSelect is the SQL expression of the calling role's own descriptor for
// $1 (scope), $2 (scope id), $3 (runs) and $4 (resources), with agents
// = [agent:<name>] of session_user (basalt_meta.agent_name): the agent is
// the one Postgres authenticated, never an argument.
const ownSelect = `jsonb_build_object('scope', $1::text, 'scopeId', $2::text, ` +
	`'agents', jsonb_build_array(basalt_meta.agent_name()), 'runs', $3::jsonb, 'resources', $4::jsonb)`

// scopeArgs are the ownSelect arguments of s. A nil list is JSON null (all).
func scopeArgs(s action.Scope) ([]any, error) {
	runs, err := json.Marshal(s.Runs)
	if err != nil {
		return nil, err
	}
	resources, err := json.Marshal(s.Tables)
	if err != nil {
		return nil, err
	}
	return []any{string(s.Kind), s.ID.String(), string(runs), string(resources)}, nil
}

// PreviewRevert returns the revert lines of the caller's own scope as
// Postgres builds them (CONTRACT.md, Revert), in COLLATE "C" order,
// redacted for the caller. It changes nothing.
func PreviewRevert(ctx context.Context, q Querier, s action.Scope) ([]string, error) {
	args, err := scopeArgs(s)
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

// PreviewRevertPage previews the caller's own scope s as PreviewRevert does,
// and reads only the totals and the limit lines after the line whose hash
// is after ("" for the first page). Postgres counts, hashes and elides,
// so a large preview or value never crosses the wire on an agent's call.
func PreviewRevertPage(ctx context.Context, q Querier, s action.Scope, after string, limit int) (action.PreviewPage, error) {
	args, err := scopeArgs(s)
	if err != nil {
		return action.PreviewPage{}, err
	}
	// Plain SQL: a set-returning function over a built descriptor, under a
	// recursive CTE (pglargevalue.ElideLines).
	sql := pglargevalue.With + `pv_all AS MATERIALIZED (
			SELECT p.n, p.t, ` + pglargevalue.SHA256Of("p.t") + ` AS hash, p.t::jsonb AS j
			FROM basalt_meta.preview_revert(` + ownSelect + `) WITH ORDINALITY AS p(t, n)
		), pv_tot AS MATERIALIZED (
			SELECT count(n) AS lines, count(n) FILTER (WHERE j->>'action' = 'RESTORE') AS restore,
				coalesce(bool_and(coalesce(j->>'conflict', '') = 'ALREADY_REVERTED'), false) AS reverted
			FROM pv_all
		), pv_cur AS MATERIALIZED (
			SELECT min(n) AS n FROM pv_all WHERE $5 <> '' AND hash = $5
		), pv_page AS MATERIALIZED (
			SELECT n, hash, j FROM pv_all WHERE n > coalesce((SELECT n FROM pv_cur), 0) ORDER BY n LIMIT $6
		), ` + pglargevalue.ElideLines(`SELECT n AS item, j AS line FROM pv_page`) + `
		SELECT t.lines, t.restore, t.reverted, $5 = '' OR (SELECT n FROM pv_cur) IS NOT NULL,
			(SELECT count(a.n) FROM pv_all a WHERE a.n > coalesce((SELECT n FROM pv_cur), 0)) > $6, p.hash, l.line::text
		FROM pv_tot t
		LEFT JOIN (pv_page p JOIN lv_lines l ON l.item = p.n) ON true
		ORDER BY p.n`
	// Only the page's lines are read; more is counted in Postgres, so a
	// page at limit 1 holds one line.
	rows, err := q.Query(ctx, sql, append(args, after, limit)...)
	if err != nil {
		return action.PreviewPage{}, err
	}
	defer rows.Close()
	var out action.PreviewPage
	for rows.Next() {
		var hash, text *string
		if err := rows.Scan(&out.Lines, &out.Restore, &out.AllAlreadyReverted, &out.CursorFound, &out.More, &hash, &text); err != nil {
			return action.PreviewPage{}, err
		}
		if text != nil {
			out.Page = append(out.Page, action.PreviewLine{Text: *text, Hash: *hash})
		}
	}
	if err := rows.Err(); err != nil {
		return action.PreviewPage{}, err
	}
	return out, nil
}

// PrepareRevert stores the caller's own proposal s for the person to sign
// (basalt_meta.prepare_revert): Postgres runs it on trial, builds the lines
// and the binding, and appends REVERT_PENDING. A TASK the caller ran in
// with no line of its own is stored as an empty proposal (Rows 0) the
// person may widen on the page; it cannot be signed as it is. Over revert.MaxLines lines
// it stores a batched plan. Call it outside a read-only transaction; a
// large plan's trial can take minutes.
func PrepareRevert(ctx context.Context, q Querier, s action.Scope, intent string) (action.PreparedRevert, error) {
	args, err := scopeArgs(s)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	var p action.PreparedRevert
	// Plain SQL: a set-returning function in FROM over a built descriptor.
	withLines := budget.From(ctx) == nil
	err = q.QueryRow(ctx, `SELECT r.revert_id, r.binding_text, r.expires_at, CASE WHEN $6 THEN r.lines END,
			coalesce(cardinality(r.lines), 0)
		FROM basalt_meta.prepare_revert(`+ownSelect+`, $5) AS r`, append(args, intent, withLines)...).
		Scan(&p.RevertID, &p.BindingText, &p.ExpiresAt, &p.Lines, &p.LineCount)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	batched, err := bindingBatched(p.BindingText)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	p.Batched = batched
	return p, nil
}

// PrepareRevertWithin prepares a revert of scope in its own transaction on
// db, with statement_timeout set to timeout for that transaction only
// (set_config(..., true)), whatever the role's default is. Past it
// Postgres cancels the prepare (SQLSTATE 57014) and nothing is stored.
// The engine's request_revert prepares through it.
func PrepareRevertWithin(ctx context.Context, db TxBeginner, s action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error) {
	if timeout < time.Millisecond {
		return action.PreparedRevert{}, guardmodel.ErrPrepareTimeout
	}
	sql, args, err := psql.Select().
		Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", strconv.FormatInt(timeout.Milliseconds(), 10))).
		ToSql()
	if err != nil {
		return action.PreparedRevert{}, err
	}
	var p action.PreparedRevert
	err = pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		var err error
		p, err = PrepareRevert(ctx, tx, s, intent)
		return err
	})
	if err != nil {
		return action.PreparedRevert{}, err
	}
	return p, nil
}

// ApplyRevert relays the person's passkey assertion for a prepared revert
// (basalt_meta.apply_revert). Postgres verifies it and, for a one-call
// revert, runs the revert in the same call; any row that changed since the
// preview refuses the whole revert with REVERT_INVALID. For a batched plan
// it records the signature and the agent then applies the plan with
// ApplyRevertBatch. Run it in its own transaction.
func ApplyRevert(ctx context.Context, q Querier, revertID uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error) {
	var out action.AppliedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.apply_revert($1::uuid, $2::bytea, $3::bytea, $4::bytea, $5::bytea)`,
		revertID.String(), a.CredentialID, a.AuthenticatorData, a.ClientDataJSON, a.Signature).
		Scan(&out)
	if err != nil {
		return action.AppliedRevert{}, err
	}
	return out, nil
}

// ApplyRevertBatch applies lines of a signed batched plan
// (basalt_meta.apply_revert_batch), as the role that prepared it. Postgres
// refuses the whole batch unless every line is in the plan and pending,
// re-checks each line with its row locked, and skips (people win) a row
// changed since the plan was built. Run it in its own transaction.
func ApplyRevertBatch(ctx context.Context, q Querier, revertID uuid.UUID, lines []int) (action.BatchResult, error) {
	var raw []byte
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.apply_revert_batch($1::uuid, $2::int[])`, revertID.String(), lines).Scan(&raw)
	if err != nil {
		return action.BatchResult{}, err
	}
	return decodeBatchResult(raw)
}

// bindingBatched reads batched from a revert binding text the guard wrote
// (CONTRACT.md, Revert, revert-binding.schema.json): only whether the plan
// is applied in batches matters here. The text is Postgres's own; the
// pages and the engine's codecs check the rest of it.
func bindingBatched(text string) (bool, error) {
	var b struct {
		Kind    string `json:"kind"`
		Batched bool   `json:"batched"`
	}
	if err := json.Unmarshal([]byte(text), &b); err != nil {
		return false, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	if b.Kind != revert.KindRevert {
		return false, fmt.Errorf("guard returned a revert binding of kind %q", b.Kind)
	}
	return b.Batched, nil
}

// batchItemJSON is one line of apply_revert_batch's answer as the guard
// writes it: the line's SQLSTATE is sqlState.
type batchItemJSON struct {
	Line     int    `json:"line"`
	Outcome  string `json:"outcome"`
	Conflict string `json:"conflict"`
	SQLState string `json:"sqlState"`
}

// batchResultJSON is apply_revert_batch's answer as the guard writes it.
type batchResultJSON struct {
	RevertID uuid.UUID       `json:"revertId"`
	Batch    int             `json:"batch"`
	Status   string          `json:"status"`
	Restored int             `json:"restored"`
	Skipped  int             `json:"skipped"`
	Pending  int             `json:"pending"`
	Items    []batchItemJSON `json:"items"`
}

// decodeBatchResult reads apply_revert_batch's jsonb answer into the
// store-neutral batch result: a line's sqlState is its StoreCode.
func decodeBatchResult(raw []byte) (action.BatchResult, error) {
	var in batchResultJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return action.BatchResult{}, fmt.Errorf("decode apply_revert_batch: %w", err)
	}
	out := action.BatchResult{
		RevertID: in.RevertID, Batch: in.Batch, Status: in.Status,
		Restored: in.Restored, Skipped: in.Skipped, Pending: in.Pending,
	}
	if in.Items != nil {
		out.Items = make([]action.BatchItem, 0, len(in.Items))
	}
	for _, it := range in.Items {
		out.Items = append(out.Items, action.BatchItem{Line: it.Line, Outcome: it.Outcome, Conflict: it.Conflict, StoreCode: it.SQLState})
	}
	return out, nil
}
