package guard

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// rlsBlindSQL lists the tables where row-level security filters role $1
// (as _rls_applies, version 8) and no permissive SELECT or ALL policy
// names $1, a role it inherits, or PUBLIC: $1 reads 0 rows there. An
// empty $1 is the session user. A role init has not created yet is judged
// as a new agent: a member of the agents group $3 (when that exists).
// $2 are the tables to check; empty checks every table $1 can SELECT.
// Plain SQL: catalog join over policies and role memberships.
const rlsBlindSQL = `WITH who AS (
    SELECT coalesce(nullif($1, ''), session_user::text) AS name
), role AS (
    SELECT r.oid, r.rolsuper, r.rolbypassrls FROM pg_catalog.pg_roles r, who WHERE r.rolname = who.name
    UNION ALL
    SELECT g.oid, false, false FROM pg_catalog.pg_roles g
     WHERE g.rolname = $3 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r, who WHERE r.rolname = who.name)
    UNION ALL
    SELECT 0::oid, false, false
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r, who WHERE r.rolname IN (who.name, $3))
)
SELECT format('%I.%I', n.nspname, c.relname)
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN role w
 WHERE c.relkind IN ('r', 'p')
   AND CASE WHEN cardinality($2::text[]) = 0
            THEN w.oid <> 0 AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'basalt_meta')
                 AND has_table_privilege(w.oid, c.oid, 'SELECT')
            ELSE c.oid = ANY (SELECT to_regclass(t) FROM unnest($2::text[]) t) END
   AND c.relrowsecurity AND NOT w.rolsuper AND NOT w.rolbypassrls
   AND (c.relforcerowsecurity
        OR NOT CASE WHEN w.oid = 0 THEN false ELSE pg_has_role(w.oid, c.relowner, 'USAGE') END)
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
                    WHERE p.polrelid = c.oid AND p.polpermissive AND p.polcmd IN ('*', 'r')
                      AND (0::oid = ANY (p.polroles)
                           OR EXISTS (SELECT 1 FROM unnest(p.polroles) pr
                                       WHERE pr <> 0
                                         AND CASE WHEN w.oid = 0 THEN false ELSE pg_has_role(w.oid, pr, 'USAGE') END)))
 ORDER BY 1`

// RLSBlindTables returns, as schema.table, the tables among tables
// ("schema.table" or "table") where row-level security is on for role and
// no policy lets it see a row, so it reads 0 rows. An empty role is the
// session user; no tables checks every table the role can SELECT.
func RLSBlindTables(ctx context.Context, q Querier, role string, tables []string) ([]string, error) {
	return rlsBlind(ctx, q, role, "", tables)
}

func rlsBlind(ctx context.Context, q Querier, role, group string, tables []string) ([]string, error) {
	idents := make([]string, 0, len(tables))
	for _, name := range tables {
		t, err := parseTable(name)
		if err != nil {
			return nil, err
		}
		idents = append(idents, t.ident())
	}
	rows, err := q.Query(ctx, rlsBlindSQL, role, idents, group)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// listedBlind is rlsBlind over the listed tables only: no tables is none,
// where rlsBlind would check the role's whole SELECT set.
func listedBlind(ctx context.Context, q Querier, role, group string, tables []string) ([]string, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	return rlsBlind(ctx, q, role, group, tables)
}

// AgentBlindTables lists the agent's --write and --read tables where
// row-level security would hide every row from its role, before or after
// init creates the role. Missing tables fail as in PlanInit. Only the
// tables in those lists count: an empty list adds none, never every table
// the role can already SELECT (a PUBLIC or agents-group grant), so an agent
// policy is never offered on a table the agent was not given.
func AgentBlindTables(ctx context.Context, q Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]guardmodel.BlindTable, error) {
	if err := checkTablesExist(ctx, q, spec); err != nil {
		return nil, err
	}
	role, err := n.Agent(spec.Name)
	if err != nil {
		return nil, err
	}
	writes, err := listedBlind(ctx, q, role, n.Agents(), spec.Write)
	if err != nil {
		return nil, err
	}
	reads, err := listedBlind(ctx, q, role, n.Agents(), spec.Read)
	if err != nil {
		return nil, err
	}
	out := make([]guardmodel.BlindTable, 0, len(writes)+len(reads))
	for _, table := range append(writes, reads...) {
		if slices.ContainsFunc(out, func(b guardmodel.BlindTable) bool { return b.Table == table }) {
			continue // a --write table listed in --read too
		}
		count, _, err := psql.Select("count(1)").From(table).ToSql()
		if err != nil {
			return nil, err
		}
		b := guardmodel.BlindTable{Table: table, Write: slices.Contains(writes, table)}
		if err := q.QueryRow(ctx, count).Scan(&b.Rows); err != nil {
			return nil, fmt.Errorf("count rows of %s: %w", table, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// agentPolicySQL lets the agent role %[1]s see every row of table %[2]s
// (decision "Agent RLS", Nov 12), FOR SELECT on a read table and FOR ALL
// on a write table (writes still pass the guard), and records it in the
// ledger. %[3]s is the command, %[4]s the table as a string literal.
const agentPolicySQL = `
CREATE POLICY %[1]s ON %[2]s AS PERMISSIVE FOR %[3]s TO %[1]s USING (true)%[5]s;
SELECT basalt_meta.record_agent_policy('%[1]s', %[4]s::regclass, '%[3]s');`

// agentPolicy is the statement for one BlindTable the person confirmed.
func agentPolicy(role string, b guardmodel.BlindTable) guardmodel.Statement {
	command, check := "SELECT", ""
	if b.Write {
		command, check = "ALL", " WITH CHECK (true)"
	}
	literal := "'" + strings.ReplaceAll(b.Table, "'", "''") + "'"
	return guardmodel.Statement{SQL: fmt.Sprintf(agentPolicySQL, role, b.Table, command, literal, check)}
}
