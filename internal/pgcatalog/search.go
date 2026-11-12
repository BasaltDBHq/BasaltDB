package pgcatalog

import (
	"context"
	"strings"
)

// Match is one relation a Search found. Rank is 0 for an exact name, 1 a
// name prefix, 2 a name containing the query, 3 a column name, 4 a comment.
type Match struct {
	Relation
	Rank int
	// Matched is "table", "column <name>" or "comment".
	Matched string
}

// SearchCursor is the last match of a page; the next page starts after it.
type SearchCursor struct {
	Rank   int
	Schema string
	Name   string
}

// likeEscaper makes a search term literal inside ILIKE.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// Search finds readable relations whose name, a selectable column name or
// comment contains q, case-insensitively, ordered by (Rank, Schema, Name).
// Columns the role cannot SELECT never match, so a search cannot confirm
// that a hidden column exists.
func Search(ctx context.Context, db Querier, q string, after *SearchCursor, limit int) ([]Match, error) {
	esc := likeEscaper.Replace(q)
	cur := SearchCursor{}
	if after != nil {
		cur = *after
	}
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT oid, nspname, relname, kind, est, comment, rank, matched FROM (
		SELECT r.*,
			CASE WHEN lower(r.relname) = lower($1) THEN 0
				WHEN r.relname ILIKE $2 THEN 1
				WHEN r.relname ILIKE $3 THEN 2
				WHEN r.col IS NOT NULL THEN 3
				WHEN r.comment ILIKE $3 THEN 4 END AS rank,
			CASE WHEN r.relname ILIKE $3 THEN 'table'
				WHEN r.col IS NOT NULL THEN 'column ' || r.col
				ELSE 'comment' END AS matched
		FROM (
			SELECT `+relationColumns+`,
				(SELECT a.attname FROM pg_catalog.pg_attribute a
					WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
					AND a.attname ILIKE $3
					AND pg_catalog.has_column_privilege(session_user, c.oid, a.attnum, 'SELECT')
					ORDER BY a.attnum LIMIT 1) AS col
			`+relationFrom+` AND `+readableTable+`
		) r
	) m
	WHERE m.rank IS NOT NULL
		AND (NOT $4::bool OR (m.rank, m.nspname, m.relname) > ($5::int, $6::text, $7::text))
	ORDER BY m.rank, m.nspname, m.relname LIMIT $8`,
		q, esc+"%", "%"+esc+"%", after != nil, cur.Rank, cur.Schema, cur.Name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Match
	for rows.Next() {
		var m Match
		if err := rows.Scan(append(m.scanTargets(), &m.Rank, &m.Matched)...); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
