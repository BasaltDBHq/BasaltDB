package pgcatalog

import (
	"context"
	"strings"
)

// Match is one relation a Search found. Rank is 0 for an exact table name, 1
// a table name prefix, 2 a table name containing the query, 3 a schema name
// containing it, 4 a column name, 5 a comment.
type Match struct {
	Relation
	Rank int
	// Matched is "table", "schema", "column <name>" or "comment".
	Matched string
}

// SearchCursor is the last match of a page; the next page starts after it.
type SearchCursor struct {
	Rank   int
	Schema string
	Name   string
}

// ColumnKey names one column by table OID and attribute number.
type ColumnKey struct {
	OID    uint32
	Attnum int16
}

// likeEscaper makes a search term literal inside ILIKE.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// Search finds readable relations whose name, schema name, a selectable
// column name or comment contains q, case-insensitively, ordered by (Rank,
// Schema, Name). Columns the role cannot SELECT never match, so a search
// cannot confirm that a hidden column exists; exclude lists further columns
// (for example ones the engine classes as secret) that never match and are
// never named in Matched.
func Search(ctx context.Context, db Querier, q string, exclude []ColumnKey, after *SearchCursor, limit int) ([]Match, error) {
	esc := likeEscaper.Replace(q)
	cur := SearchCursor{}
	if after != nil {
		cur = *after
	}
	exOIDs := make([]uint32, 0, len(exclude))
	exNums := make([]int16, 0, len(exclude))
	for _, k := range exclude {
		exOIDs = append(exOIDs, k.OID)
		exNums = append(exNums, k.Attnum)
	}
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT oid, nspname, relname, kind, est, comment, rank, matched,
			p_select, p_insert, p_update, p_delete FROM (
		SELECT r.*,
			CASE WHEN lower(r.relname) = lower($1) THEN 0
				WHEN r.relname ILIKE $2 THEN 1
				WHEN r.relname ILIKE $3 THEN 2
				WHEN r.nspname ILIKE $3 THEN 3
				WHEN r.col IS NOT NULL THEN 4
				WHEN r.comment ILIKE $3 THEN 5 END AS rank,
			CASE WHEN r.relname ILIKE $3 THEN 'table'
				WHEN r.nspname ILIKE $3 THEN 'schema'
				WHEN r.col IS NOT NULL THEN 'column ' || r.col
				ELSE 'comment' END AS matched
		FROM (
			SELECT `+relationColumns+`,
				(SELECT a.attname FROM pg_catalog.pg_attribute a
					WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
					AND a.attname ILIKE $3
					AND pg_catalog.has_column_privilege(session_user, c.oid, a.attnum, 'SELECT')
					AND NOT EXISTS (SELECT 1 FROM unnest($9::oid[], $10::int2[]) AS x(o, n)
						WHERE x.o = c.oid AND x.n = a.attnum)
					ORDER BY a.attnum LIMIT 1) AS col,
				`+privilegeColumns+`
			`+relationFrom+` AND `+readableTable+`
		) r
	) m
	WHERE m.rank IS NOT NULL
		AND (NOT $4::bool OR (m.rank, m.nspname, m.relname) > ($5::int, $6::text, $7::text))
	ORDER BY m.rank, m.nspname, m.relname LIMIT $8`,
		q, esc+"%", "%"+esc+"%", after != nil, cur.Rank, cur.Schema, cur.Name, limit, exOIDs, exNums)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Match
	for rows.Next() {
		var m Match
		var privs [4]bool
		if err := rows.Scan(append(m.scanTargets(), &m.Rank, &m.Matched, &privs[0], &privs[1], &privs[2], &privs[3])...); err != nil {
			return nil, err
		}
		m.Privileges = privilegeNames(privs)
		out = append(out, m)
	}
	return out, rows.Err()
}
