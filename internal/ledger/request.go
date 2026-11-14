package ledger

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"

	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
)

// The request a held write's or revert's link carries is its binding text
// and its lines (CONTRACT.md, Large values, Requests too large for a link).
// On an agent's call (a context with a result budget), Postgres measures
// them first, and reads the lines only when binding and lines together are
// at most MaxRequestText of text and MaxRequestCost in the budget's unit.
// Otherwise the lines come back as their heads (each line without its
// value images: op, table and flags, enough to count them), LinesLeftOut
// is set, and the engine hands the request over only on a short link that
// can carry it, or answers REQUEST_TOO_LARGE. Reads with no budget (the
// person's CLI, the pages API) read the lines in full.
const (
	// MaxRequestText caps the text of binding and lines read on an agent's
	// call: what a page decodes is at most 1 MiB of rebuilt texts.
	MaxRequestText = 1 << 20
	// MaxRequestCost caps their cost in the budget's unit.
	MaxRequestCost = 4 << 20
)

// textCost is the SQL of what one text t costs in the budget's unit: its
// bytes, 6 more for each byte JSON escapes, and the per-value overhead.
func textCost(t string) string {
	return fmt.Sprintf("(octet_length(%[1]s) + 6 * %[2]s + 128)", t, largevalue.EscapesOf(t))
}

// requestJoin measures the binding text and lines of the row being read
// (rq.fits, rq.lines_cost).
var requestJoin = fmt.Sprintf(`CROSS JOIN LATERAL (
	SELECT m.text_bytes <= %[1]d AND m.cost <= %[2]d AS fits, m.lines_cost
	FROM (
		SELECT octet_length(coalesce(binding_text, '')) + coalesce(sum(octet_length(u.x)), 0) AS text_bytes,
			%[3]s + coalesce(sum(%[4]s), 0) AS cost,
			coalesce(sum(%[4]s), 0)::bigint AS lines_cost
		FROM unnest(coalesce(lines, '{}')) AS u(x)
	) m
) rq`, MaxRequestText, MaxRequestCost, textCost("coalesce(binding_text, '')"), textCost("u.x"))

// headsOf is the SQL of the lines' heads: each line without its value
// images.
const headsOf = `ARRAY(SELECT (h.x::jsonb - 'key' - 'old' - 'set' - 'now')::text
	FROM unnest(coalesce(lines, '{}')) WITH ORDINALITY AS h(x, n) ORDER BY h.n)`

// withRequest adds the lines and their measure to b, which reads from a
// table with binding_text and lines: measured on an agent's call
// (requestJoin), in full otherwise. The columns are lines, lines_left_out
// and lines_cost.
func withRequest(ctx context.Context, b sq.SelectBuilder) sq.SelectBuilder {
	if resultsize.From(ctx) == nil {
		return b.Columns("coalesce(lines, '{}') AS lines", "false AS lines_left_out", "0::bigint AS lines_cost")
	}
	return b.Columns(
		"CASE WHEN rq.fits THEN coalesce(lines, '{}') ELSE "+headsOf+" END AS lines",
		"NOT rq.fits AS lines_left_out", "rq.lines_cost").
		JoinClause(requestJoin)
}
