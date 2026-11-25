package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// Agent reads with large values left out (CONTRACT.md, Large values): the
// engine's run_history, list_pending and revert_plan read through these, so
// a large value never crosses the wire on an agent's call. ListChanges,
// RowChanges and ListRevertLines read the same rows in full.

// Positions of a change record's images in its item, before its rows': a
// row's key, before and after are at seq*imagesPerRow + 0, 1 and 2.
const (
	ordStatement = -2
	ordParams    = -1
	imagesPerRow = 3
)

// headerImages selects a statement and its params as images (item id)
// from rel, which has id, statement and params.
func headerImages(rel, id string) string {
	return fmt.Sprintf(`SELECT %[6]s AS item, %[2]d AS ord, '%[4]s' AS part, to_jsonb(statement) AS img FROM %[1]s
		UNION ALL SELECT %[6]s, %[3]d, '%[5]s', params FROM %[1]s`,
		rel, ordStatement, ordParams, largevalue.InStatement, largevalue.InParams, id)
}

// The statement and params of a markedPage row as an agent reads them, and
// their largeValues. The row past the limit, read only to tell that
// another page follows, has no statement (no lv_head image) and no params.
var (
	markedStatement = `coalesce(st.img #>> '{}', '')`
	markedParams    = `CASE WHEN p.lv_more THEN NULL WHEN pa.item IS NULL THEN p.params ELSE pa.img END`
	markedLarge     = largevalue.Join("st.large_values", "pa.large_values")
)

// pageOnly is the SQL of expr for a page row, and empty for the row past
// the limit (markedPage's lv_more): that row only tells that another page
// follows, and its values are never read (CONTRACT.md, Large values: a page
// at limit 1 holds one item).
func pageOnly(expr, empty string) string {
	return fmt.Sprintf("CASE WHEN p.lv_more THEN %s ELSE %s END", empty, expr)
}

// markedPage reads the rows page selects (each with id, statement and
// params; at most limit and one more, in order) as cols, in order, with
// the statement and params of each elided as one item (markedStatement,
// markedParams, markedLarge). The row past limit has lv_more set and none
// of its values elided or read.
func markedPage(page, id, order string, limit int, cols ...string) string {
	// Plain SQL: a recursive CTE over the page (largevalue.Elide).
	return largevalue.With + `lv_page AS MATERIALIZED (SELECT x.*, row_number() OVER (ORDER BY ` + order + `) > ` +
		fmt.Sprint(limit) + ` AS lv_more FROM (` + page + `) x), lv_head AS MATERIALIZED (` +
		headerImages("(SELECT * FROM lv_page WHERE NOT lv_more) h", id) + `), ` +
		largevalue.Elide(`SELECT * FROM lv_head`) + fmt.Sprintf(`
		SELECT %[1]s FROM lv_page p
		LEFT JOIN lv_out st ON st.item = p.%[2]s AND st.ord = %[3]d
		LEFT JOIN lv_out pa ON pa.item = p.%[2]s AND pa.ord = %[4]d
		ORDER BY p.%[5]s`, strings.Join(cols, ", "), id, ordStatement, ordParams, order)
}

// ListChangesMarked is ListChanges for an agent: a statement or params
// that is too large is left out (empty Statement, nil Params) and named in
// LargeValues.
func ListChangesMarked(ctx context.Context, q guard.Querier, p action.ChangeListParams) (pagination.Page[action.Change], error) {
	page, args, desc, err := changePage(p)
	if err != nil {
		return pagination.Page[action.Change]{}, err
	}
	order := colChangeID
	if desc {
		order += descending
	}
	sql := markedPage(page, colChangeID, order, p.Limit, "p.change_id", "p.at", "p.agent", "p.run_id", "p.task_id", "p.intent", "p.op",
		"p.table_name", markedStatement, markedParams, "p.rows", "p.cascaded_rows", "p.duration_ms", "p.status", "p.code",
		"p.reason", "p.actor_kind", "p.revert_id", "p.reverted_by", "p.verb", markedLarge)
	return collectChanges(ctx, q, p, sql, args, func(row pgx.CollectableRow, c *action.Change) error {
		var large []byte
		if err := row.Scan(append(changeDest(c), &large)...); err != nil {
			return err
		}
		return unmarshalEntries(large, &c.LargeValues)
	})
}

// RowChangesMarked is RowChanges for an agent: each change is one item
// (its statement, params, then each row's key, before and after by seq),
// with the values and images too large left out and named.
func RowChangesMarked(ctx context.Context, q guard.Querier, changeIDs []uuid.UUID) (map[uuid.UUID][]action.RowChange, error) {
	out := make(map[uuid.UUID][]action.RowChange, len(changeIDs))
	if len(changeIDs) == 0 {
		return out, nil
	}
	rowsSQL, args, err := rowChangeSelect(changeIDs).ToSql()
	if err != nil {
		return nil, err
	}
	// Plain SQL: a recursive CTE over the rows (largevalue.Elide).
	sql := largevalue.With + `lv_rc AS MATERIALIZED (` + rowsSQL + `),
		lv_ch AS MATERIALIZED (SELECT change_id, statement, params FROM basalt_meta.agent_changes WHERE change_id IN (SELECT change_id FROM lv_rc)),
		lv_imgs AS MATERIALIZED (` + headerImages("lv_ch", colChangeID) + fmt.Sprintf(`
			UNION ALL SELECT change_id, seq * %[1]d, '%[2]s', row_key FROM lv_rc
			UNION ALL SELECT change_id, seq * %[1]d + 1, '%[3]s', old_row FROM lv_rc
			UNION ALL SELECT change_id, seq * %[1]d + 2, '%[4]s', new_row FROM lv_rc), `,
		imagesPerRow, largevalue.InKey, largevalue.InBefore, largevalue.InAfter) +
		largevalue.Elide(`SELECT * FROM lv_imgs`) + fmt.Sprintf(`
		SELECT r.change_id, r.seq, r.table_name, r.op,
			CASE WHEN k.item IS NULL THEN r.row_key ELSE k.img END, k.item IS NOT NULL AND k.img IS NULL,
			CASE WHEN b.item IS NULL THEN r.old_row ELSE b.img END, b.item IS NOT NULL AND b.img IS NULL,
			CASE WHEN a.item IS NULL THEN r.new_row ELSE a.img END, a.item IS NOT NULL AND a.img IS NULL,
			r.cascaded, r.redacted, r.values_pruned, r.based_on, r.blind_write, %[2]s
		FROM lv_rc r
		LEFT JOIN lv_out k ON k.item = r.change_id AND k.ord = r.seq * %[1]d
		LEFT JOIN lv_out b ON b.item = r.change_id AND b.ord = r.seq * %[1]d + 1
		LEFT JOIN lv_out a ON a.item = r.change_id AND a.ord = r.seq * %[1]d + 2
		ORDER BY r.seq`, imagesPerRow, largevalue.Join("k.large_values", "b.large_values", "a.large_values"))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var r action.RowChange
		var large []byte
		if err := rows.Scan(&id, &r.Seq, &r.Table, &r.Op, &r.Key, &r.KeyLeftOut, &r.Before, &r.BeforeLeftOut,
			&r.After, &r.AfterLeftOut, &r.Cascaded, &r.Redacted, &r.Pruned, &r.BasedOn, &r.BlindWrite, &large); err != nil {
			return nil, err
		}
		if err := unmarshalEntries(large, &r.LargeValues); err != nil {
			return nil, err
		}
		out[id] = append(out[id], r)
	}
	return out, rows.Err()
}

// unmarshalEntries reads a largeValues array; NULL leaves dst nil.
func unmarshalEntries(raw []byte, dst *[]largevalue.Entry) error {
	if raw == nil {
		return nil
	}
	return json.Unmarshal(raw, dst)
}
