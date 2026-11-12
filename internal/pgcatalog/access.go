package pgcatalog

import (
	"context"
	"sort"
)

// Access lists user-schema relations as schema.table, sorted: what
// session_user can read, what it can write, and what it cannot read.
type Access struct {
	Read       []string
	Write      []string
	NotGranted []string
}

// ListAccess classifies every user-schema relation by session_user's table
// privileges. Write means INSERT, UPDATE or DELETE.
func ListAccess(ctx context.Context, db Querier) (Access, error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT n.nspname || '.' || c.relname, `+readableTable+`,
			pg_catalog.has_table_privilege(session_user, c.oid, 'INSERT')
			OR pg_catalog.has_table_privilege(session_user, c.oid, 'UPDATE')
			OR pg_catalog.has_table_privilege(session_user, c.oid, 'DELETE')
		`+relationFrom)
	if err != nil {
		return Access{}, err
	}
	defer rows.Close()
	var acc Access
	for rows.Next() {
		var name string
		var read, write bool
		if err := rows.Scan(&name, &read, &write); err != nil {
			return Access{}, err
		}
		if read {
			acc.Read = append(acc.Read, name)
		} else {
			acc.NotGranted = append(acc.NotGranted, name)
		}
		if write {
			acc.Write = append(acc.Write, name)
		}
	}
	if err := rows.Err(); err != nil {
		return Access{}, err
	}
	// Sorted in Go so the order does not depend on the database collation.
	sort.Strings(acc.Read)
	sort.Strings(acc.Write)
	sort.Strings(acc.NotGranted)
	return acc, nil
}
