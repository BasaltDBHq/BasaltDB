package guard

import (
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// allTablesSQL lists the ordinary and partitioned tables of schema $1, as
// schema.table, with their owner, whether the connected role owns them and
// whether they have a primary key (the guard keys an agent's writes by it)
// (agent.allTables, CONTRACT.md, The setup code). Partitions are left out:
// the agent reaches their rows through the partitioned table. Only plain
// lowercase identifiers are listed, the names a setup code's tables may
// have. Plain SQL: a catalog read squirrel cannot express (the owner's name
// and the comparison with current_user).
const allTablesSQL = `SELECT n.nspname || '.' || c.relname,
       r.rolname,
       r.rolname = current_user,
       EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p')
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
 WHERE n.nspname = $1
   AND c.relkind IN ('r', 'p')
   AND NOT c.relispartition
   AND c.relname ~ '^[a-z_][a-z0-9_]{0,62}$'
 ORDER BY 1`

// SchemaTables are the tables of a schema as an agent.allTables setup sees
// them, each in name order.
type SchemaTables struct {
	// Write are the tables the connected role owns that have a primary key:
	// the agent may change their rows.
	Write []string
	// ReadOnly are the tables the connected role owns without a primary
	// key: the guard cannot key an agent's writes there, so the agent may
	// only read them.
	ReadOnly []string
	// Excluded are the tables another role owns.
	Excluded []setupcode.ExcludedTable
}

// AllTablesIn reads the tables of schema for an agent.allTables setup.
func AllTablesIn(ctx context.Context, q Querier, schema string) (SchemaTables, error) {
	var out SchemaTables
	rows, err := q.Query(ctx, allTablesSQL, schema)
	if err != nil {
		return out, fmt.Errorf("list the tables of schema %s: %w", schema, err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, owner string
		var mine, keyed bool
		if err := rows.Scan(&table, &owner, &mine, &keyed); err != nil {
			return SchemaTables{}, err
		}
		switch {
		case !mine:
			out.Excluded = append(out.Excluded, setupcode.ExcludedTable{Table: table, Owner: owner})
		case keyed:
			out.Write = append(out.Write, table)
		default:
			out.ReadOnly = append(out.ReadOnly, table)
		}
	}
	return out, rows.Err()
}

// grantedTablesSQL lists the ordinary and partitioned tables role $1 holds
// a privilege on itself (on the table or one of its columns), outside the
// system schemas and basalt_meta, as schema.table of plain lowercase
// identifiers, in name order: the agent's tables as its grants record them.
const grantedTablesSQL = `SELECT DISTINCT n.nspname || '.' || c.relname
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p')
   AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'basalt_meta'
   AND n.nspname ~ '^[a-z_][a-z0-9_]{0,62}$' AND c.relname ~ '^[a-z_][a-z0-9_]{0,62}$'
   AND (EXISTS (SELECT 1 FROM pg_catalog.aclexplode(c.relacl) a, pg_catalog.pg_roles r WHERE r.rolname = $1 AND a.grantee = r.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute t, LATERAL pg_catalog.aclexplode(t.attacl) a, pg_catalog.pg_roles r
                   WHERE t.attrelid = c.oid AND r.rolname = $1 AND a.grantee = r.oid))
 ORDER BY 1`

// GrantedTables are the tables role holds a privilege on (grantedTablesSQL):
// what an AGENT setup code that keeps the role's grants leaves it.
func GrantedTables(ctx context.Context, q Querier, role string) ([]string, error) {
	rows, err := q.Query(ctx, grantedTablesSQL, role)
	if err != nil {
		return nil, fmt.Errorf("read the agent's tables: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
