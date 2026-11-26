package setupstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// The local setup page's reads of the catalog and the session: the tables an
// install lists, the columns of the picked ones, and who a connection is.

// CatalogTable is one table of an install's listing, as the catalog has it:
// its schema-qualified name, its owner, whether the connection's role owns
// it, whether it has a primary key, and whether its name is a plain
// lowercase identifier. It is an alias of the struct itself, so the setup's
// port names the same type with no import of this package.
type CatalogTable = struct {
	Name  string
	Owner string
	Mine  bool
	Keyed bool
	Plain bool
}

// listSQL reads the ordinary and partitioned tables of the schemas $1 (one
// more than the cap, so a longer list is known). Plain SQL: a catalog read
// squirrel cannot express. Partitions are left out: the agent reaches their
// rows through the partitioned table.
const listSQL = `SELECT n.nspname || '.' || c.relname,
       r.rolname,
       r.rolname = current_user,
       EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p'),
       c.relname ~ '^` + setupcode.PlainName + `$'
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
 WHERE n.nspname = ANY($1)
   AND c.relkind IN ('r', 'p')
   AND NOT c.relispartition
 ORDER BY n.nspname COLLATE "C", c.relname COLLATE "C"
 LIMIT $2`

// ListTables reads at most limit tables of schemas, in schema and table
// order (listSQL). It stops reading once it has limit rows: what the
// server sends after the last one is not read, as the listing's cap
// answers "more" without it.
func (Store) ListTables(ctx context.Context, q sqlport.Port, schemas []string, limit int) ([]CatalogTable, error) {
	rows, err := q.Query(ctx, listSQL, schemas, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CatalogTable
	for len(out) < limit && rows.Next() {
		var t CatalogTable
		if err := rows.Scan(&t.Name, &t.Owner, &t.Mine, &t.Keyed, &t.Plain); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// columnsSQL reads the ordinary columns of the picked tables, with their
// schema and table names apart, in table and column order, at most $2.
const columnsSQL = `SELECT n.nspname::text, c.relname::text, a.attname::text,
       pg_catalog.format_type(a.atttypid, NULL)
  FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS t(name, ord)
  JOIN pg_catalog.pg_namespace n ON n.nspname::text = pg_catalog.split_part(t.name, '.', 1)
  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname::text = pg_catalog.split_part(t.name, '.', 2)
  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
 WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
 ORDER BY t.ord, a.attnum
 LIMIT $2`

// ListColumns reads at most limit ordinary columns of tables
// (schema-qualified names), in the tables' order and then the columns'
// (columnsSQL). Each column carries its namespace, table, name and data type.
func (Store) ListColumns(ctx context.Context, q sqlport.Port, tables []string, limit int) ([]piistore.Column, error) {
	rows, err := q.Query(ctx, columnsSQL, tables, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []piistore.Column
	for rows.Next() {
		var c piistore.Column
		if err := rows.Scan(&c.Namespace, &c.Resource, &c.Name, &c.DataType); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// IsMember reports whether role is a member of group (pg_has_role MEMBER).
func (Store) IsMember(ctx context.Context, q sqlport.Port, role, group string) (bool, error) {
	var member bool
	err := q.QueryRow(ctx, `SELECT pg_catalog.pg_has_role($1, $2, 'MEMBER')`, role, group).Scan(&member)
	return member, err
}

// CurrentUser is current_user on q.
func (Store) CurrentUser(ctx context.Context, q sqlport.Port) (string, error) {
	var user string
	// A SQL keyword squirrel cannot express.
	err := q.QueryRow(ctx, `SELECT current_user::text`).Scan(&user)
	return user, err
}

// SessionUser is session_user on q: the role the connection logged in as.
func (Store) SessionUser(ctx context.Context, q sqlport.Port) (string, error) {
	var user string
	// A SQL keyword squirrel cannot express.
	err := q.QueryRow(ctx, `SELECT session_user::text`).Scan(&user)
	return user, err
}

// CurrentUserAndDatabase is current_user and current_database() on q, read
// in one statement.
func (Store) CurrentUserAndDatabase(ctx context.Context, q sqlport.Port) (user, database string, err error) {
	err = q.QueryRow(ctx, `SELECT current_user::text, pg_catalog.current_database()::text`).Scan(&user, &database)
	return user, database, err
}

// DatabaseError is the message and detail of the Postgres error in err;
// false when err carries none. The code is setup.SQLStateOf's.
func (Store) DatabaseError(err error) (message, detail string, ok bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", "", false
	}
	return pg.Message, pg.Detail, true
}

// CommitAnswered reports whether a failed commit's outcome is known: the
// database answered it with an error, it became a rollback, or the driver
// never sent it. Any other failure may have committed.
func (Store) CommitAnswered(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) || errors.Is(err, pgx.ErrTxCommitRollback) || pgconn.SafeToRetry(err)
}
