package guard

import (
	"context"
	"encoding/json"
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
	Tables    []string
	Rows      int
	Duration  time.Duration
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
	tables := r.Tables
	if tables == nil {
		tables = []string{}
	}
	return returnUUID(ctx, q, sq.Expr(
		"basalt_meta.record_read(?::uuid, ?, nullif(?::jsonb, 'null'), ?::text[], ?::int, ?::int, ?::jsonb)",
		nullUUID(r.RunID), r.Statement, params, tables, r.Rows, r.Duration.Milliseconds(), string(versions)))
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
