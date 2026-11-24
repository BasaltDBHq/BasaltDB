package pgcatalog

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Relation is one table, view, materialized view or partitioned table the
// session's role can read. Partitions are never listed on their own.
type Relation struct {
	OID    uint32
	Schema string
	Name   string
	// Kind is TABLE, VIEW, MATERIALIZED_VIEW or PARTITIONED_TABLE.
	Kind string
	// EstimatedRows is nil when the relation was never analyzed.
	EstimatedRows *int64
	// Comment is the catalog text, untrimmed.
	Comment string
	// Privileges lists SELECT, INSERT, UPDATE and DELETE as held by
	// session_user, SELECT by the visibility rule (readableTable).
	Privileges []string
}

// userSchemaFilter keeps a query to user schemas: not the system schemas,
// toast and temp schemas, basalt_meta, or a schema that is itself a member
// of an extension. A schema an extension merely installs into (public, say)
// stays; notExtensionRelation drops the relations the extension owns. It
// expects the pg_namespace row aliased n. The underscores in the LIKE
// patterns are escaped because the schema names mean them literally.
const userSchemaFilter = `n.nspname NOT IN ('pg_catalog', 'information_schema', 'basalt_meta')
	AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
	AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_namespace'::regclass
		AND d.objid = n.oid AND d.deptype = 'e')`

// notExtensionRelation drops relations that belong to an extension (for
// example pg_stat_statements views). It expects the pg_class row aliased c.
const notExtensionRelation = `NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend xd
	WHERE xd.classid = 'pg_catalog.pg_class'::regclass AND xd.objid = c.oid AND xd.deptype = 'e')`

// readableTable is true when session_user can SELECT from the relation: a
// table-level grant, or a grant on at least one column (a column-grant table
// is visible, only its ungranted columns are not).
const readableTable = `pg_catalog.has_any_column_privilege(session_user, c.oid, 'SELECT')`

// relationKind maps pg_class.relkind to the Relation.Kind names.
const relationKind = `CASE c.relkind WHEN 'r' THEN 'TABLE' WHEN 'v' THEN 'VIEW'
		WHEN 'm' THEN 'MATERIALIZED_VIEW' ELSE 'PARTITIONED_TABLE' END`

// relationColumns and relationFrom select the Relation fields over every
// user-schema relation that is not a partition. A partitioned parent reports
// its own estimate when it has one, else the summed estimate of its analyzed
// leaves.
const relationColumns = `c.oid, n.nspname AS nspname, c.relname AS relname,
	` + relationKind + ` AS kind,
	CASE WHEN c.reltuples >= 0 THEN c.reltuples::bigint
	WHEN c.relkind = 'p' THEN
		(SELECT sum(l.reltuples)::bigint FROM pg_catalog.pg_partition_tree(c.oid) t
			JOIN pg_catalog.pg_class l ON l.oid = t.relid WHERE t.isleaf AND l.reltuples >= 0)
	END AS est,
	COALESCE(pg_catalog.obj_description(c.oid, 'pg_class'), '') AS comment`

const relationFrom = `FROM pg_catalog.pg_class c
	JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
	WHERE c.relkind IN ('r', 'v', 'm', 'p') AND NOT c.relispartition AND ` + userSchemaFilter + ` AND ` + notExtensionRelation

// privilegeColumns selects session_user's SELECT, INSERT, UPDATE and DELETE
// rights, in that order. SELECT follows readableTable so a column-grant table
// reports it, consistent with visibility.
const privilegeColumns = readableTable + ` AS p_select,
	pg_catalog.has_table_privilege(session_user, c.oid, 'INSERT') AS p_insert,
	pg_catalog.has_table_privilege(session_user, c.oid, 'UPDATE') AS p_update,
	pg_catalog.has_table_privilege(session_user, c.oid, 'DELETE') AS p_delete`

// privilegeNames turns the four flags of privilegeColumns into names.
func privilegeNames(flags [4]bool) []string {
	var out []string
	for i, name := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if flags[i] {
			out = append(out, name)
		}
	}
	return out
}

func (r *Relation) scanTargets() []any {
	return []any{&r.OID, &r.Schema, &r.Name, &r.Kind, &r.EstimatedRows, &r.Comment}
}

// Relations lists the relations session_user can read, ordered by schema and
// name, and counts the ones it cannot, without naming them.
func Relations(ctx context.Context, db Querier) (visible []Relation, notGranted int, err error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT `+relationColumns+`, `+privilegeColumns+` `+relationFrom+`
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Relation
		var privs [4]bool
		if err := rows.Scan(append(r.scanTargets(), &privs[0], &privs[1], &privs[2], &privs[3])...); err != nil {
			return nil, 0, err
		}
		if !privs[0] {
			notGranted++
			continue
		}
		r.Privileges = privilegeNames(privs)
		visible = append(visible, r)
	}
	return visible, notGranted, rows.Err()
}

// FindRelation returns schema.name, or false when it is absent or
// session_user cannot read it (the two look the same on purpose).
func FindRelation(ctx context.Context, db Querier, schema, name string) (Relation, bool, error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT `+relationColumns+`, `+privilegeColumns+` `+relationFrom+`
		AND n.nspname = $1 AND c.relname = $2 AND `+readableTable, schema, name)
	if err != nil {
		return Relation{}, false, err
	}
	r, err := pgx.CollectOneRow(rows, func(row pgx.CollectableRow) (Relation, error) {
		var r Relation
		var privs [4]bool
		err := row.Scan(append(r.scanTargets(), &privs[0], &privs[1], &privs[2], &privs[3])...)
		r.Privileges = privilegeNames(privs)
		return r, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Relation{}, false, nil
	}
	if err != nil {
		return Relation{}, false, err
	}
	return r, true, nil
}
