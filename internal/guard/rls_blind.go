package guard

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// rlsBlindSQL lists the tables where row-level security filters $1's
// access (as _rls_applies, version 8) and no permissive SELECT or ALL
// policy names $1, a role it inherits, or PUBLIC: $1 reads 0 rows there.
// $2 are the tables to check; empty checks every table $1 can SELECT.
// Plain SQL: catalog join over policies and role memberships.
const rlsBlindSQL = `SELECT format('%I.%I', n.nspname, c.relname)
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_roles r ON r.rolname = coalesce(nullif($1, ''), session_user)
 WHERE c.relkind IN ('r', 'p')
   AND CASE WHEN cardinality($2::text[]) = 0
            THEN n.nspname NOT IN ('pg_catalog', 'information_schema', 'basalt_meta')
                 AND has_table_privilege(r.oid, c.oid, 'SELECT')
            ELSE c.oid = ANY (SELECT to_regclass(t) FROM unnest($2::text[]) t) END
   AND c.relrowsecurity AND NOT r.rolsuper AND NOT r.rolbypassrls
   AND (c.relforcerowsecurity OR NOT pg_has_role(r.oid, c.relowner, 'USAGE'))
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
                    WHERE p.polrelid = c.oid AND p.polpermissive AND p.polcmd IN ('*', 'r')
                      AND (0::oid = ANY (p.polroles)
                           OR EXISTS (SELECT 1 FROM unnest(p.polroles) pr
                                       WHERE pr <> 0 AND pg_has_role(r.oid, pr, 'USAGE'))))
 ORDER BY 1`

// RLSBlindTables returns, as schema.table, the tables among tables
// ("schema.table" or "table") where row-level security is on for role and
// no policy lets it see a row, so it reads 0 rows. An empty role is the
// session user; no tables checks every table the role can SELECT. Basalt
// never adds a policy for an agent (decision N12-7): this only reports.
func RLSBlindTables(ctx context.Context, q Querier, role string, tables []string) ([]string, error) {
	idents := make([]string, 0, len(tables))
	for _, name := range tables {
		t, err := parseTable(name)
		if err != nil {
			return nil, err
		}
		idents = append(idents, t.ident())
	}
	rows, err := q.Query(ctx, rlsBlindSQL, role, idents)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
