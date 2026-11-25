// Package pglargevalue builds the SQL that leaves large values out of what
// the ledger tools read for an agent, by the rules of
// internal/core/largevalue (CONTRACT.md, Large values). Postgres measures
// every value in the result budget's unit, leaves out each value over
// largevalue.ValueCap and every image that would take its item over
// largevalue.ItemCap, and returns a marker with the value's size and
// SHA-256 in its place, so a large value never crosses the wire on an
// agent's call.
package pglargevalue

import (
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
)

// TextOf is the SQL text of a jsonb value v as the marker measures and
// hashes it: a JSON string's characters, anything else its jsonb text.
func TextOf(v string) string {
	return fmt.Sprintf(`(CASE WHEN jsonb_typeof(%[1]s) = 'string' THEN %[1]s #>> '{}' ELSE %[1]s::text END)`, v)
}

// BytesOf and SHA256Of are the SQL of the marker's bytes and sha256 over
// the text t, in UTF-8.
func BytesOf(t string) string { return fmt.Sprintf(`octet_length(convert_to(%s, 'UTF8'))`, t) }

// SHA256Of is the lowercase hex SHA-256 of the text t in UTF-8.
func SHA256Of(t string) string {
	return fmt.Sprintf(`encode(sha256(convert_to(%s, 'UTF8')), 'hex')`, t)
}

// jsonEscapable are the bytes JSON escapes that can appear in JSON text as
// Postgres prints it: it writes every control byte as an escape (\n,
// \u0001), so of the bytes JSON escapes only these five remain.
var jsonEscapable = []string{`'"'`, `'\'`, `'<'`, `'>'`, `'&'`}

// EscapesOf is the SQL count of the bytes JSON escapes in the JSON text t
// (as Postgres prints it). One replace per byte: far faster over megabytes
// than a regular expression or translate that removes them.
func EscapesOf(t string) string {
	terms := make([]string, 0, len(jsonEscapable))
	for _, c := range jsonEscapable {
		terms = append(terms, fmt.Sprintf("(octet_length(%[1]s) - octet_length(replace(%[1]s, %[2]s, '')))", t, c))
	}
	return "(" + strings.Join(terms, " + ") + ")"
}

// CostOf is the SQL of what a value costs whose JSON text (as Postgres
// prints it: a string with its quotes and escapes) is t, in column col. The
// cost is taken over the JSON text, not the marker's text, because that is
// what a read of the image carries: a string of '"' is 2 bytes a character
// on the wire, so a cost over its characters would undercount it by half.
func CostOf(t, col string) string {
	return fmt.Sprintf(`(%[3]s + %[4]d * %[5]s + %[6]d + octet_length(coalesce(%[2]s, '')))`,
		t, col, BytesOf(t), largevalue.EscapeCost, EscapesOf(t), largevalue.ValueOverhead)
}

// With starts a statement that uses Elide or ElideLines: lv_keep is
// recursive, and RECURSIVE goes on the WITH of the whole statement.
const With = "WITH RECURSIVE "

// Elide returns the WITH entries (after With) that read the images src
// selects, with columns item (any type), ord (bigint, the order within the
// item), part (one of the In constants) and img (jsonb: an object for a row
// image, an array for PARAMS, a JSON string for STATEMENT). It ends in
// lv_out (item, ord, part, img, large_values): img is NULL when the image
// is left out whole, large_values the image's entries or NULL. An image
// that is NULL or JSON null has no lv_out row.
//
// The rules (CONTRACT.md, Large values, Which values): a value over
// largevalue.ValueCap is left out of its image (a STATEMENT, or the whole PARAMS
// array, with it); then, in ord order, an image is kept while the item's
// running cost (kept values plus the entries of values left out) stays at
// most largevalue.ItemCap, and is otherwise left out whole with one entry that
// replaces its values' entries.
func Elide(src string) string {
	return fmt.Sprintf(elideSQL, src,
		TextOf("c.val"), BytesOf("t.txt"), quickCost("v.js", "v.col"), SHA256Of("t.txt"),
		largevalue.ValueCap, largevalue.EntryCost, largevalue.ItemCap, BytesOf(TextOf("i.img")), SHA256Of(TextOf("i.img")))
}

// quickCost is CostOf for the JSON text js in column col, without counting
// escapes when its bytes alone are already over largevalue.ValueCap: such a value is
// left out whatever it costs, and counting escapes over megabytes is what
// takes the time.
func quickCost(js, col string) string {
	plain := fmt.Sprintf(`(octet_length(%[1]s) + %[2]d + octet_length(coalesce(%[3]s, '')))`, js, largevalue.ValueOverhead, col)
	return fmt.Sprintf(`(CASE WHEN %[1]s > %[2]d THEN %[1]s ELSE %[3]s END)`, plain, largevalue.ValueCap, CostOf(js, col))
}

// elideSQL is Elide's template. lv_keep is a recursive CTE: whether an
// image is kept depends on the images kept before it. Every step is
// MATERIALIZED: the planner cannot know how many rows a page has, and
// must not rescan an aggregate for each of them. lv_vals keeps each
// value's JSON text, so it is built once, not once per reference (Postgres
// does not share a repeated expression); the marker's text, size and hash
// are computed only for the values left out.
const elideSQL = `lv_src AS MATERIALIZED (
	SELECT s.item, s.ord::bigint AS ord, s.part, s.img FROM (%[1]s) s
	WHERE s.img IS NOT NULL AND jsonb_typeof(s.img) <> 'null'
), lv_vals AS MATERIALIZED (
	SELECT s.item, s.ord, v.col, v.idx, v.val, v.val::text AS js
	FROM lv_src s
	CROSS JOIN LATERAL (
		SELECT e.key AS col, NULL::int AS idx, e.value AS val
		FROM jsonb_each(CASE WHEN jsonb_typeof(s.img) = 'object' THEN s.img END) AS e
		UNION ALL
		SELECT NULL, (a.n - 1)::int, a.value
		FROM jsonb_array_elements(CASE WHEN s.part = 'PARAMS' AND jsonb_typeof(s.img) = 'array' THEN s.img END)
			WITH ORDINALITY AS a(value, n)
		UNION ALL
		SELECT NULL, NULL, s.img WHERE s.part = 'STATEMENT'
	) v
), lv_cost AS MATERIALIZED (
	SELECT v.item, v.ord, v.col, v.idx, v.val, %[4]s::bigint AS cost FROM lv_vals v
), lv_large AS MATERIALIZED (
	SELECT c.item, c.ord,
		array_agg(c.col) FILTER (WHERE c.col IS NOT NULL) AS cols,
		jsonb_agg(jsonb_strip_nulls(jsonb_build_object('field', c.col, 'index', c.idx, 'bytes', %[3]s, 'sha256', %[5]s))
			ORDER BY c.idx, c.col COLLATE "C") AS entries
	FROM lv_cost c CROSS JOIN LATERAL (SELECT %[2]s AS txt OFFSET 0) t
	WHERE c.cost > %[6]d GROUP BY c.item, c.ord
), lv_img AS MATERIALIZED (
	SELECT s.item, s.ord, s.part, s.img,
		coalesce(c.nlarge, 0) AS nlarge,
		(coalesce(c.nlarge, 0) * %[7]d + CASE WHEN s.part = 'PARAMS' AND c.nlarge > 0 THEN 0 ELSE coalesce(c.small, 0) END)::bigint AS cost,
		row_number() OVER (PARTITION BY s.item ORDER BY s.ord) AS rn
	FROM lv_src s
	LEFT JOIN (
		SELECT item, ord, sum(cost) FILTER (WHERE cost <= %[6]d) AS small, count(cost) FILTER (WHERE cost > %[6]d) AS nlarge
		FROM lv_cost GROUP BY item, ord
	) c ON c.item = s.item AND c.ord = s.ord
), lv_keep AS MATERIALIZED (
	SELECT item, rn, cost <= %[8]d AS kept, CASE WHEN cost <= %[8]d THEN cost ELSE 0 END::bigint AS run
	FROM lv_img WHERE rn = 1
	UNION ALL
	SELECT i.item, i.rn, k.run + i.cost <= %[8]d, (k.run + CASE WHEN k.run + i.cost <= %[8]d THEN i.cost ELSE 0 END)::bigint
	FROM lv_keep k JOIN lv_img i ON i.item = k.item AND i.rn = k.rn + 1
), lv_out AS MATERIALIZED (
	SELECT i.item, i.ord, i.part,
		CASE
			WHEN NOT k.kept THEN NULL
			WHEN i.nlarge > 0 AND i.part IN ('PARAMS', 'STATEMENT') THEN NULL
			WHEN i.nlarge > 0 THEN i.img - g.cols
			ELSE i.img
		END AS img,
		CASE
			WHEN NOT k.kept THEN jsonb_build_array(jsonb_build_object('in', i.part, 'bytes', %[9]s, 'sha256', %[10]s))
			ELSE (SELECT jsonb_agg(jsonb_build_object('in', i.part) || x.e ORDER BY x.n)
				FROM jsonb_array_elements(g.entries) WITH ORDINALITY AS x(e, n))
		END AS large_values
	FROM lv_img i
	JOIN lv_keep k ON k.item = i.item AND k.rn = i.rn
	LEFT JOIN lv_large g ON g.item = i.item AND g.ord = i.ord
)`

// ElideLines returns the WITH entries (after With) that read revert lines
// as an agent may: lines selects item (any type) and line (jsonb, the
// signed line). It ends in lv_lines (item, line jsonb): the line with its
// key, now and set images elided as Elide does, largeValues when any value
// was left out, and at most largevalue.MaxChangeIDs changeIds with moreChangeIds
// counting the rest.
func ElideLines(lines string) string {
	src := fmt.Sprintf(`SELECT item, 1 AS ord, '%s' AS part, line->'key' AS img FROM lv_line_src
		UNION ALL SELECT item, 2, '%s', line->'now' FROM lv_line_src
		UNION ALL SELECT item, 3, '%s', line->'set' FROM lv_line_src`, largevalue.InKey, largevalue.InNow, largevalue.InSet)
	return fmt.Sprintf(linesSQL, lines, Elide(src), largevalue.MaxChangeIDs)
}

// linesSQL is ElideLines' template. An image left out whole is removed
// from the line; a kept one replaces the original.
const linesSQL = `lv_line_src AS MATERIALIZED (%[1]s), %[2]s, lv_parts AS MATERIALIZED (
	SELECT item,
		array_agg(lower(part)) AS parts,
		jsonb_object_agg(lower(part), img) FILTER (WHERE img IS NOT NULL) AS kept
	FROM lv_out GROUP BY item
), lv_entries AS MATERIALIZED (
	SELECT o.item, jsonb_agg(x.e ORDER BY o.ord, x.n) AS large_values
	FROM lv_out o CROSS JOIN LATERAL jsonb_array_elements(o.large_values) WITH ORDINALITY AS x(e, n)
	GROUP BY o.item
), lv_lines AS MATERIALIZED (
	SELECT l.item,
		(l.line - coalesce(p.parts, '{}'::text[])) || coalesce(p.kept, '{}'::jsonb)
		|| CASE WHEN e.large_values IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('largeValues', e.large_values) END
		|| CASE WHEN jsonb_typeof(l.line->'changeIds') = 'array' AND jsonb_array_length(l.line->'changeIds') > %[3]d
			THEN jsonb_build_object(
				'changeIds', (SELECT jsonb_agg(c.id ORDER BY c.n) FROM jsonb_array_elements(l.line->'changeIds') WITH ORDINALITY AS c(id, n) WHERE c.n <= %[3]d),
				'moreChangeIds', jsonb_array_length(l.line->'changeIds') - %[3]d)
			ELSE '{}'::jsonb END AS line
	FROM lv_line_src l
	LEFT JOIN lv_parts p ON p.item = l.item
	LEFT JOIN lv_entries e ON e.item = l.item
)`

// Join concatenates the largeValues arrays of SQL expressions, NULL when
// none has an entry.
func Join(arrays ...string) string {
	parts := make([]string, 0, len(arrays))
	for _, a := range arrays {
		parts = append(parts, fmt.Sprintf("coalesce(%s, '[]'::jsonb)", a))
	}
	return fmt.Sprintf("NULLIF(%s, '[]'::jsonb)", strings.Join(parts, " || "))
}
