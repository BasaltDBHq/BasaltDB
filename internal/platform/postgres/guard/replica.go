package guard

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/lib/sqlident"
)

// Where the database default of session_replication_role comes from, in
// the order Postgres applies them (the first one found wins).
const (
	replicaSourceDatabase = "DATABASE"  // ALTER DATABASE ... SET
	replicaSourceAllRoles = "ALL_ROLES" // ALTER ROLE ALL SET
	replicaSourceServer   = "SERVER"    // postgresql.conf, ALTER SYSTEM, the command line
)

// replicationRoleWarning reads the default of session_replication_role a
// new agent session in this database gets, and returns a warning naming
// the fix when it is not origin ("" when it is, or when it cannot tell).
// The guard's triggers are ENABLE ALWAYS from version 26, so they fire in
// any mode; the warning is for everything else that does not: foreign keys
// and the person's own triggers. The agent role's own settings are reset
// by init (agentAdoptSQL), so they are not read here. It only reads the
// catalog.
func replicationRoleWarning(ctx context.Context, q Querier) (string, error) {
	var value, source, db string
	// Plain SQL: a catalog query over pg_db_role_setting and pg_settings.
	err := q.QueryRow(ctx, `
		SELECT x.v, x.src, pg_catalog.current_database()::text FROM (
		    SELECT 1 AS ord, pg_catalog.split_part(c, '=', 2) AS v, $1 AS src
		      FROM pg_catalog.pg_db_role_setting s, pg_catalog.unnest(s.setconfig) c
		     WHERE s.setrole = 0 AND c LIKE 'session\_replication\_role=%'
		       AND s.setdatabase = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database())
		    UNION ALL
		    SELECT 2, pg_catalog.split_part(c, '=', 2), $2
		      FROM pg_catalog.pg_db_role_setting s, pg_catalog.unnest(s.setconfig) c
		     WHERE s.setrole = 0 AND s.setdatabase = 0 AND c LIKE 'session\_replication\_role=%'
		    UNION ALL
		    -- The admin's own role settings hide the server's value: skip.
		    SELECT 3, p.reset_val, $3 FROM pg_catalog.pg_settings p
		     WHERE p.name = 'session_replication_role' AND p.source NOT IN ('user', 'database user')
		) x ORDER BY x.ord LIMIT 1`,
		replicaSourceDatabase, replicaSourceAllRoles, replicaSourceServer).Scan(&value, &source, &db)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if value == "origin" {
		return "", nil
	}
	fix := map[string]string{
		replicaSourceDatabase: fmt.Sprintf("ALTER DATABASE %s RESET session_replication_role;", sqlident.Quote(db)),
		replicaSourceAllRoles: "ALTER ROLE ALL RESET session_replication_role;",
		replicaSourceServer:   "ALTER SYSTEM RESET session_replication_role; SELECT pg_reload_conf(); (and remove it from postgresql.conf if it is set there)",
	}[source]
	return fmt.Sprintf("the database default of session_replication_role is %s, not origin. "+
		"The guard's triggers fire anyway, but in agent sessions foreign keys are not enforced and your own triggers do not fire. "+
		"To fix it, as a superuser run: %s", value, fix), nil
}
