package pgcatalog

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Column is one column of a relation. Name and Type are returned even when
// Selectable is false so the caller can count what it hides; it must not
// show them.
type Column struct {
	Attnum int16
	Name   string
	// Type is the text format_type prints.
	Type     string
	Nullable bool
	// Default is the pg_get_expr text, empty when there is none.
	Default string
	// DefaultAttnums are the columns the default or generated expression reads.
	DefaultAttnums []int16
	Generated      bool
	Comment        string
	// Selectable is has_column_privilege(session_user, ..., 'SELECT').
	Selectable bool
}

// Index is one index of a relation.
type Index struct {
	Name       string
	Definition string
	// Attnums are the key and INCLUDE columns plus the columns read by
	// expressions and the predicate.
	Attnums   []int16
	Unique    bool
	Partial   bool
	SizeBytes int64
	Scans     int64
}

// Key is one foreign key touching a relation, seen from that relation.
type Key struct {
	Name     string
	Outgoing bool
	// Attnums are the key columns on this relation.
	Attnums  []int16
	OtherOID uint32
	// OtherSchema, OtherTable and OtherColumns are empty when the other
	// relation is not readable by session_user: a hidden table is counted,
	// never named.
	OtherSchema   string
	OtherTable    string
	OtherColumns  []string
	OtherReadable bool
	// OnDelete and OnUpdate are CASCADE, SET NULL, SET DEFAULT, RESTRICT or
	// NO ACTION.
	OnDelete string
	OnUpdate string
}

// Stats is the size and scan activity of a relation. LastAnalyzed is nil
// when it never was.
type Stats struct {
	TableBytes   int64
	TotalBytes   int64
	SeqScans     int64
	IndexScans   int64
	LastAnalyzed *time.Time
}

// Detail is everything describe reports about one relation.
type Detail struct {
	Relation
	Columns    []Column
	PrimaryKey []int16
	Indexes    []Index
	Keys       []Key
	Stats      Stats
	RLS        bool
	// Privileges lists SELECT, INSERT, UPDATE and DELETE as held by session_user.
	Privileges []string
	// CascadesIntoHidden is how many distinct unreadable tables a DELETE here
	// reaches, transitively over CASCADE, SET NULL and SET DEFAULT.
	CascadesIntoHidden int
}

// DescribeRelation reads one relation by OID. The caller gets the OID from
// Relations or FindRelation, so it is already known to be readable.
func DescribeRelation(ctx context.Context, db Querier, oid uint32) (Detail, error) {
	var d Detail
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT `+relationColumns+`, c.relrowsecurity,
			pg_catalog.has_table_privilege(session_user, c.oid, 'SELECT'),
			pg_catalog.has_table_privilege(session_user, c.oid, 'INSERT'),
			pg_catalog.has_table_privilege(session_user, c.oid, 'UPDATE'),
			pg_catalog.has_table_privilege(session_user, c.oid, 'DELETE')
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE c.oid = $1 AND c.relkind IN ('r', 'v', 'm', 'p')`, oid)
	if err != nil {
		return Detail{}, err
	}
	var privs [4]bool
	d, err = pgx.CollectOneRow(rows, func(row pgx.CollectableRow) (Detail, error) {
		var d Detail
		targets := append(d.scanTargets(), &d.RLS, &privs[0], &privs[1], &privs[2], &privs[3])
		err := row.Scan(targets...)
		return d, err
	})
	if err != nil {
		return Detail{}, err
	}
	for i, name := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if privs[i] {
			d.Privileges = append(d.Privileges, name)
		}
	}

	if d.Columns, err = columnsOf(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	if d.PrimaryKey, err = primaryKeyAttnums(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	if d.Indexes, err = indexesOf(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	if d.Keys, err = keysOf(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	if d.Stats, err = statsOf(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	if d.CascadesIntoHidden, err = cascadesIntoHidden(ctx, db, oid); err != nil {
		return Detail{}, err
	}
	return d, nil
}

func columnsOf(ctx context.Context, db Querier, oid uint32) ([]Column, error) {
	// Plain SQL: a pg_catalog read, not table DML. The default's column
	// references come from pg_depend on the pg_attrdef row; a generated
	// column also depends on itself, which is not a reference.
	rows, err := db.Query(ctx, `SELECT a.attnum, a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod),
			NOT a.attnotnull,
			COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), ''),
			COALESCE(array(SELECT DISTINCT dep.refobjsubid::int2 FROM pg_catalog.pg_depend dep
				WHERE dep.classid = 'pg_catalog.pg_attrdef'::regclass AND dep.objid = d.oid
				AND dep.refobjid = a.attrelid AND dep.refobjsubid > 0
				AND dep.refobjsubid <> a.attnum ORDER BY 1), '{}'::int2[]),
			a.attgenerated <> '',
			COALESCE(pg_catalog.col_description(a.attrelid, a.attnum), ''),
			pg_catalog.has_column_privilege(session_user, a.attrelid, a.attnum, 'SELECT')
		FROM pg_catalog.pg_attribute a
		LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, oid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Column, error) {
		var c Column
		err := row.Scan(&c.Attnum, &c.Name, &c.Type, &c.Nullable, &c.Default, &c.DefaultAttnums,
			&c.Generated, &c.Comment, &c.Selectable)
		return c, err
	})
}

func primaryKeyAttnums(ctx context.Context, db Querier, oid uint32) ([]int16, error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT COALESCE(array(
			SELECT u.k FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS u(k, o) WHERE u.k > 0 ORDER BY u.o
		), '{}'::int2[])
		FROM pg_catalog.pg_index i WHERE i.indrelid = $1 AND i.indisprimary`, oid)
	if err != nil {
		return nil, err
	}
	pk, err := pgx.CollectOneRow(rows, pgx.RowTo[[]int16])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return pk, err
}

func indexesOf(ctx context.Context, db Querier, oid uint32) ([]Index, error) {
	// Plain SQL: a pg_catalog read, not table DML. Columns used by index
	// expressions and the predicate are not in indkey; Postgres records them
	// in pg_depend, so no index definition text is parsed.
	rows, err := db.Query(ctx, `SELECT ic.relname::text, pg_catalog.pg_get_indexdef(i.indexrelid),
			COALESCE(array(SELECT DISTINCT s.k FROM (
				SELECT unnest(i.indkey::int2[]) AS k
				UNION ALL
				SELECT dep.refobjsubid::int2 FROM pg_catalog.pg_depend dep
				WHERE dep.classid = 'pg_catalog.pg_class'::regclass AND dep.objid = i.indexrelid
				AND dep.refobjid = i.indrelid AND dep.refobjsubid > 0
			) s WHERE s.k > 0 ORDER BY s.k), '{}'::int2[]),
			i.indisunique, i.indpred IS NOT NULL,
			pg_catalog.pg_relation_size(i.indexrelid),
			COALESCE(st.idx_scan, 0)
		FROM pg_catalog.pg_index i
		JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
		LEFT JOIN pg_catalog.pg_stat_user_indexes st ON st.indexrelid = i.indexrelid
		WHERE i.indrelid = $1
		ORDER BY ic.relname`, oid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Index, error) {
		var x Index
		err := row.Scan(&x.Name, &x.Definition, &x.Attnums, &x.Unique, &x.Partial, &x.SizeBytes, &x.Scans)
		return x, err
	})
}

// keysOf returns the foreign keys leaving and entering the relation. The
// other relation's names are blanked in SQL unless session_user can read it.
func keysOf(ctx context.Context, db Querier, oid uint32) ([]Key, error) {
	// Plain SQL: a pg_catalog read, not table DML.
	rows, err := db.Query(ctx, `SELECT k.conname::text, k.outgoing, k.mine, k.other_oid,
			CASE WHEN k.readable THEN on_.nspname::text ELSE '' END,
			CASE WHEN k.readable THEN oc.relname::text ELSE '' END,
			CASE WHEN k.readable THEN array(
				SELECT oa.attname::text FROM unnest(k.theirs) WITH ORDINALITY AS u(n, o)
				JOIN pg_catalog.pg_attribute oa ON oa.attrelid = k.other_oid AND oa.attnum = u.n
				ORDER BY u.o) ELSE '{}'::text[] END,
			k.readable,
			CASE k.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE'
				WHEN 'n' THEN 'SET NULL' ELSE 'SET DEFAULT' END,
			CASE k.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE'
				WHEN 'n' THEN 'SET NULL' ELSE 'SET DEFAULT' END
		FROM (
			SELECT x.conname, x.confdeltype, x.confupdtype,
				x.conrelid = $1 AS outgoing,
				CASE WHEN x.conrelid = $1 THEN x.conkey ELSE x.confkey END AS mine,
				CASE WHEN x.conrelid = $1 THEN x.confkey ELSE x.conkey END AS theirs,
				CASE WHEN x.conrelid = $1 THEN x.confrelid ELSE x.conrelid END AS other_oid,
				pg_catalog.has_any_column_privilege(session_user,
					CASE WHEN x.conrelid = $1 THEN x.confrelid ELSE x.conrelid END, 'SELECT') AS readable
			FROM pg_catalog.pg_constraint x
			WHERE x.contype = 'f' AND (x.conrelid = $1 OR x.confrelid = $1)
		) k
		JOIN pg_catalog.pg_class oc ON oc.oid = k.other_oid
		JOIN pg_catalog.pg_namespace on_ ON on_.oid = oc.relnamespace
		ORDER BY k.outgoing DESC, k.conname, k.other_oid`, oid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Key, error) {
		var k Key
		err := row.Scan(&k.Name, &k.Outgoing, &k.Attnums, &k.OtherOID, &k.OtherSchema, &k.OtherTable,
			&k.OtherColumns, &k.OtherReadable, &k.OnDelete, &k.OnUpdate)
		return k, err
	})
}

func statsOf(ctx context.Context, db Querier, oid uint32) (Stats, error) {
	// Plain SQL: a pg_catalog and pg_stat_user_tables read, never pg_stats
	// (which holds sampled column values) and never table rows.
	rows, err := db.Query(ctx, `SELECT pg_catalog.pg_relation_size(c.oid), pg_catalog.pg_total_relation_size(c.oid),
			COALESCE(st.seq_scan, 0), COALESCE(st.idx_scan, 0),
			GREATEST(st.last_analyze, st.last_autoanalyze)
		FROM pg_catalog.pg_class c
		LEFT JOIN pg_catalog.pg_stat_user_tables st ON st.relid = c.oid
		WHERE c.oid = $1`, oid)
	if err != nil {
		return Stats{}, err
	}
	return pgx.CollectOneRow(rows, func(row pgx.CollectableRow) (Stats, error) {
		var s Stats
		err := row.Scan(&s.TableBytes, &s.TotalBytes, &s.SeqScans, &s.IndexScans, &s.LastAnalyzed)
		return s, err
	})
}

// cascadesIntoHidden walks the foreign keys that propagate a DELETE (CASCADE,
// SET NULL, SET DEFAULT) breadth-first from the relation and counts the
// distinct tables on the way that session_user cannot read.
func cascadesIntoHidden(ctx context.Context, db Querier, oid uint32) (int, error) {
	visited := map[uint32]bool{oid: true}
	frontier := []uint32{oid}
	hidden := 0
	for len(frontier) > 0 {
		// Plain SQL: a pg_catalog read, not table DML.
		rows, err := db.Query(ctx, `SELECT DISTINCT x.conrelid::oid,
				pg_catalog.has_any_column_privilege(session_user, x.conrelid, 'SELECT')
			FROM pg_catalog.pg_constraint x
			WHERE x.contype = 'f' AND x.confdeltype IN ('c', 'n', 'd') AND x.confrelid = ANY($1::oid[])`, frontier)
		if err != nil {
			return 0, err
		}
		type reach struct {
			oid      uint32
			readable bool
		}
		reached, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (reach, error) {
			var r reach
			err := row.Scan(&r.oid, &r.readable)
			return r, err
		})
		if err != nil {
			return 0, err
		}
		frontier = frontier[:0]
		for _, r := range reached {
			if visited[r.oid] {
				continue
			}
			visited[r.oid] = true
			frontier = append(frontier, r.oid)
			if !r.readable {
				hidden++
			}
		}
	}
	return hidden, nil
}
