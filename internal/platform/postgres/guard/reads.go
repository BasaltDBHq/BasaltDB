package guard

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
)

// RowVersion is one row a read saw: its guarded table, primary key and
// version (xmin, as decimal text).
type RowVersion struct {
	TableOID uint32
	// Key is a JSON object of the table's primary-key columns, as
	// jsonb_build_object renders them.
	Key     json.RawMessage
	Version string
}

// Read is one read the engine ran for the agent (owner decision #7).
type Read struct {
	// RunID is uuid.Nil for a read outside a run.
	RunID     uuid.UUID
	Statement string
	Params    []any
	// Tables are the relations the statement names, as written; they are
	// recorded qualified (qualifiedResources).
	Tables   []string
	Rows     int
	Duration time.Duration
	// Versions are the rows the engine could identify; empty for
	// aggregates and other statements without row identity.
	Versions []RowVersion
}

// versionJSON is one entry of record_read's versions argument.
type versionJSON struct {
	TableOID uint32          `json:"tableOid"`
	Key      json.RawMessage `json:"key"`
	Version  string          `json:"version"`
}

// RecordRead records a read: a SELECT change record, a READ ledger row,
// and for a run the version of each row it saw, which the guard checks
// later writes of the run against (STALE_READ). Call it after the read's
// own read-only transaction. It returns the change id.
func RecordRead(ctx context.Context, q Querier, r Read) (uuid.UUID, error) {
	params, err := paramsJSON(r.Params)
	if err != nil {
		return uuid.Nil, err
	}
	entries := make([]versionJSON, 0, len(r.Versions))
	for _, v := range r.Versions {
		entries = append(entries, versionJSON(v))
	}
	versions, err := json.Marshal(entries)
	if err != nil {
		return uuid.Nil, err
	}
	return returnUUID(ctx, q, sq.Expr(
		"basalt_meta.record_read(?::uuid, ?, nullif(?::jsonb, 'null'), ?, ?::int, ?::int, ?::jsonb)",
		nullUUID(r.RunID), r.Statement, params, qualifiedResources(r.Tables), r.Rows, r.Duration.Milliseconds(),
		string(versions)))
}

// qualifiedResourcesSQL is a text[] of the names given ($1 as written, $2
// and $3 their schema and relation parts, nameParts) as the ledger names a
// resource: schema.table, each part quoted where needed, the form a write's
// regclass takes under the guard's search_path (pg_catalog, pg_temp). It is
// evaluated in the caller's session, outside the SECURITY DEFINER function,
// so an unqualified name resolves as the agent's own statement did:
// to_regclass with the agent's search_path, which skips schemas it cannot
// use and raises nothing. A qualified name needs no lookup, so a schema the
// agent cannot use cannot keep a refusal out of the ledger. A name that
// does not resolve, or does not split into at most two parts, is kept as
// written. In the order given, each resource once (its first place).
//
// Every function and operator is pg_catalog's: this runs under the agent's
// search_path, where a function or operator it created could otherwise
// win. The CASE keeps to_regclass from ever seeing an empty name (which
// raises before Postgres 16), whatever order the planner picks. ROWS FROM
// zips the three arrays; the multi-argument unnest is FROM-clause sugar
// for it with no pg_catalog function to qualify.
const qualifiedResourcesSQL = `ARRAY(SELECT x.r FROM (
    SELECT CASE WHEN n.nsp OPERATOR(pg_catalog.<>) '' THEN pg_catalog.format('%I.%I', n.nsp, n.rel)
                ELSE coalesce((SELECT pg_catalog.format('%I.%I', s.nspname, c.relname)
                                 FROM pg_catalog.pg_class c
                                 JOIN pg_catalog.pg_namespace s ON s.oid OPERATOR(pg_catalog.=) c.relnamespace
                                WHERE c.oid OPERATOR(pg_catalog.=) (CASE WHEN n.rel OPERATOR(pg_catalog.<>) ''
                                      THEN pg_catalog.to_regclass(pg_catalog.quote_ident(n.rel)) END)::pg_catalog.oid),
                              n.name) END AS r,
           n.i
      FROM ROWS FROM (pg_catalog.unnest(?::text[]), pg_catalog.unnest(?::text[]), pg_catalog.unnest(?::text[]))
           WITH ORDINALITY AS n(name, nsp, rel, i)) x
  GROUP BY x.r ORDER BY pg_catalog.min(x.i))`

// qualifiedResources is names, the relations a statement names as
// written, qualified when recorded (qualifiedResourcesSQL).
func qualifiedResources(names []string) sq.Sqlizer {
	written, schemas, rels := nameParts(names)
	return sq.Expr(qualifiedResourcesSQL, written, schemas, rels)
}

// nameParts splits each name as the SQL check writes it (parser-folded,
// unquoted, schema.table or table) into its schema and relation; a name of
// more parts has neither and is recorded as written. Known limit: a quoted
// identifier that holds a dot splits wrongly, so "public.payroll" (one
// relation in the search path) is recorded as the table payroll in schema
// public, with no lookup; every name the engine takes as schema.table has
// the same limit. It changes only which name a refusal records, never what
// the guard allows.
func nameParts(names []string) (written, schemas, rels []string) {
	written = make([]string, 0, len(names))
	schemas = make([]string, 0, len(names))
	rels = make([]string, 0, len(names))
	for _, name := range names {
		schema, rel := "", name
		switch parts := strings.Split(name, "."); len(parts) {
		case 1:
		case 2:
			schema, rel = parts[0], parts[1]
			if schema == "" || rel == "" {
				schema, rel = "", ""
			}
		default:
			rel = ""
		}
		written, schemas, rels = append(written, name), append(schemas, schema), append(rels, rel)
	}
	return written, schemas, rels
}

// GuardedTable is a guarded table the agent can read.
type GuardedTable struct {
	// Table is the qualified name.
	Table  string
	OID    uint32
	PKCols []string
}

// ResolveGuarded resolves relation names as the agent's session would
// (to_regclass, same search_path) and returns, keyed by the name given,
// those that are guarded tables the agent can SELECT. Views, CTE names,
// unguarded, unreadable and missing relations are left out. Names are SQL
// identifiers, quoted where needed.
func ResolveGuarded(ctx context.Context, q Querier, names []string) (map[string]GuardedTable, error) {
	out := map[string]GuardedTable{}
	if len(names) == 0 {
		return out, nil
	}
	// Plain SQL: unnest joined to the agent view on to_regclass.
	rows, err := q.Query(ctx, `SELECT n.name, g.table_name, g.table_oid, g.pk_cols
		FROM unnest($1::text[]) AS n(name)
		JOIN basalt_meta.agent_guarded_tables g ON g.table_oid = pg_catalog.to_regclass(n.name)::oid`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var g GuardedTable
		if err := rows.Scan(&name, &g.Table, &g.OID, &g.PKCols); err != nil {
			return nil, err
		}
		out[name] = g
	}
	return out, rows.Err()
}
