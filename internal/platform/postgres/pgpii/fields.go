package pgpii

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// pageWaitMargin is how long a page may wait for a connection, on top of
// the agent's statement timeout.
const pageWaitMargin = time.Minute

// SQLSTATEs that make the scan skip one table and go on: the table or
// column is gone, or the agent may no longer read it (ErrUnreadable). Its
// values then drop out of the next base, as values the agent cannot read
// should. A statement timeout skips only a relation read in one pass
// (ErrTooSlow).
const (
	scanStateUndefinedTable  = "42P01"
	scanStateUndefinedColumn = "42703"
	scanStateInsufficient    = "42501"
	scanStateQueryCanceled   = "57014"
)

// Relation kinds (pg_class.relkind) that have a ctid to page by.
const (
	relkindTable        = "r"
	relkindMaterialized = "m"
)

// FieldReader reads the values of one agent's IDENTIFIER columns for the
// dictionary scan (pii.Fields), on the agent's pool.
type FieldReader struct {
	pool        Pool
	limits      sqlguard.Limits
	loadTimeout time.Duration
}

// Fields reads through the agent's pool: each page in a read-only
// transaction of its own under the agent's statement timeout (limits), and
// a table's relkind and key under loadTimeout, so a pool with no free
// connection cannot hold the scan for good. It panics on a nil pool or a
// load timeout that is not positive.
func Fields(pool Pool, limits sqlguard.Limits, loadTimeout time.Duration) *FieldReader {
	if pool == nil || loadTimeout <= 0 {
		panic("pgpii: pool and load timeout required")
	}
	return &FieldReader{pool: pool, limits: limits, loadTimeout: loadTimeout}
}

// Read pages through one table: by its primary key, or by ctid for a table
// or materialized view without one. A relation with neither (a view, a
// partitioned or foreign table without a key) is read in one pass, under
// the agent's statement timeout: a timeout there is ErrTooSlow instead of
// a failure. A table gone or no longer readable is ErrUnreadable. value
// gets each non-null value: json and jsonb as json.RawMessage, every other
// type as its text. page gets each page's row count after the page's
// transaction has closed.
func (f *FieldReader) Read(ctx context.Context, t piistore.ScanTarget, pageRows int,
	value func(field int, v any) error, page func(rows int) error,
) error {
	oid, err := scanOID(t.Resource)
	if err != nil {
		return err
	}
	kctx, cancel := context.WithTimeout(ctx, f.loadTimeout)
	keys, relkind, err := keysetOf(kctx, f.pool, oid)
	cancel()
	if err != nil {
		return unreadable(err)
	}
	if len(keys) == 0 && relkind != relkindTable && relkind != relkindMaterialized {
		err := f.pageAll(ctx, onePassPager(t), pageRows, value, page)
		if hasState(err, scanStateQueryCanceled) {
			return fmt.Errorf("%w: %w", piistore.ErrTooSlow, err)
		}
		return unreadable(err)
	}
	if len(keys) == 0 {
		keys = []keyColumn{{name: "ctid", typ: "tid", system: true}}
	}
	return unreadable(f.pageAll(ctx, rowPager(t, keys, pageRows), pageRows, value, page))
}

// scanOID reads a resource ref back as the table's oid, as agentcatalog
// writes it. A ref this adapter did not write is an engine defect: it
// fails the cycle, never a guess.
func scanOID(ref agentstore.ResourceRef) (uint32, error) {
	oid, err := strconv.ParseUint(string(ref), 10, 32)
	if err != nil || oid == 0 || strconv.FormatUint(oid, 10) != string(ref) {
		return 0, fmt.Errorf("pgpii: %q is not a table the scan can read", ref)
	}
	return uint32(oid), nil
}

// unreadable wraps err in piistore.ErrUnreadable when Postgres says the
// table or a column is gone, or the agent may no longer read it.
func unreadable(err error) error {
	if hasState(err, scanStateUndefinedTable) || hasState(err, scanStateUndefinedColumn) || hasState(err, scanStateInsufficient) {
		return fmt.Errorf("%w: %w", piistore.ErrUnreadable, err)
	}
	return err
}

// hasState reports whether err is a Postgres error with SQLSTATE code.
func hasState(err error, code string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == code
}

// errRelationGone is a relation dropped after the classes named it.
var errRelationGone = fmt.Errorf("%w: the table is gone", piistore.ErrUnreadable)

// keyColumn is one column of the keyset a table is paged by.
type keyColumn struct {
	name, typ string
	// system is ctid, which is not quoted as an identifier.
	system bool
}

func (k keyColumn) sql() string {
	if k.system {
		return k.name
	}
	return pgx.Identifier{k.name}.Sanitize()
}

// keysetOf reads a table's relkind and its primary key columns with their
// types; no key when any key column is not readable by the agent.
func keysetOf(ctx context.Context, db Querier, oid uint32) ([]keyColumn, string, error) {
	q, args, err := sqlport.Builder.Select("relkind::text").From("pg_catalog.pg_class").Where(sq.Eq{"oid": oid}).ToSql()
	if err != nil {
		return nil, "", err
	}
	relRows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	var (
		relkind, kind string
		found         bool
	)
	if err := forEachRow(relRows, []any{&kind}, func() error {
		if !found {
			relkind, found = kind, true
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	if !found {
		return nil, "", errRelationGone
	}
	// Plain SQL: a catalog query over the unnested index key, which
	// squirrel cannot express.
	rows, err := db.Query(ctx, `SELECT a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod),
		       coalesce(pg_catalog.has_column_privilege(a.attrelid, a.attnum, 'SELECT'), false)
		  FROM pg_catalog.pg_index i
		 CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		 WHERE i.indrelid = $1 AND i.indisprimary
		 ORDER BY k.ord`, oid)
	if err != nil {
		return nil, "", err
	}
	var (
		keys     []keyColumn
		k        keyColumn
		readable bool
		all      = true
	)
	err = forEachRow(rows, []any{&k.name, &k.typ, &readable}, func() error {
		keys = append(keys, k)
		all = all && readable
		return nil
	})
	if err != nil || !all {
		return nil, relkind, err
	}
	return keys, relkind, nil
}

// pager builds one page's statement from the cursor (nil for the first
// page). Each row holds keyCols cursor columns, then one value per field of
// the target.
type pager struct {
	query   func(cursor []string) (string, []any, error)
	keyCols int
	// onePass is a single statement with no LIMIT: its one page is all.
	onePass bool
}

// rowPager pages a table by its keyset, all IDENTIFIER columns at once:
// SELECT k…, c… FROM t WHERE (k…) > (cursor) ORDER BY k… LIMIT page.
func rowPager(t piistore.ScanTarget, keys []keyColumn, page int) pager {
	sel := make([]string, 0, len(keys)+len(t.Fields))
	order := make([]string, 0, len(keys))
	bounds := make([]string, 0, len(keys))
	for _, k := range keys {
		sel = append(sel, k.sql())
		order = append(order, k.sql())
		// The type is format_type's output, already quoted where needed.
		bounds = append(bounds, "CAST(? AS "+k.typ+")")
	}
	for _, c := range t.Fields {
		sel = append(sel, pgx.Identifier{c.Field}.Sanitize())
	}
	from := pgx.Identifier{t.Namespace, t.Name}.Sanitize()
	tuple := "(" + strings.Join(order, ", ") + ") > (" + strings.Join(bounds, ", ") + ")"
	return pager{
		keyCols: len(keys),
		query: func(cursor []string) (string, []any, error) {
			b := sqlport.Builder.Select(sel...).From(from).OrderBy(order...).Limit(uint64(page))
			if cursor != nil {
				b = b.Where(sq.Expr(tuple, toArgs(cursor)...))
			}
			return b.ToSql()
		},
	}
}

// onePassPager reads a relation without a keyset in one streamed
// statement, all IDENTIFIER columns at once: SELECT c… FROM t. It reads
// each row once (no per-page re-sort of the whole relation), and the
// agent's statement timeout bounds it.
func onePassPager(t piistore.ScanTarget) pager {
	sel := make([]string, 0, len(t.Fields))
	for _, c := range t.Fields {
		sel = append(sel, pgx.Identifier{c.Field}.Sanitize())
	}
	from := pgx.Identifier{t.Namespace, t.Name}.Sanitize()
	return pager{
		onePass: true,
		query: func([]string) (string, []any, error) {
			return sqlport.Builder.Select(sel...).From(from).ToSql()
		},
	}
}

func toArgs(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// pageAll reads every page of p and hands each page's row count to page,
// once that page's transaction has closed.
func (f *FieldReader) pageAll(ctx context.Context, p pager, pageRows int, value func(int, any) error, page func(int) error) error {
	var cursor []string
	for {
		next, n, err := f.page(ctx, p, cursor, value)
		if err != nil {
			return err
		}
		if err := page(n); err != nil {
			return err
		}
		if p.onePass || n < pageRows {
			return nil
		}
		cursor = next
	}
}

// page reads one page in its own read-only transaction under the agent's
// statement timeout, in Postgres's text format, and returns the cursor
// after its last row. The transaction is rolled back before it returns.
func (f *FieldReader) page(ctx context.Context, p pager, cursor []string, value func(int, any) error) ([]string, int, error) {
	q, args, err := p.query(cursor)
	if err != nil {
		return nil, 0, err
	}
	// The statement timeout bounds the query; the margin bounds the wait
	// for a connection.
	ctx, cancel := context.WithTimeout(ctx, f.limits.StatementTimeout+pageWaitMargin)
	defer cancel()
	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, err
	}
	// Read-only: nothing to commit.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	timeout, targs, err := sqlport.StatementTimeoutSQL(f.limits.StatementTimeout)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, timeout, targs...); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(ctx, q, append([]any{pgx.QueryResultFormats{pgx.TextFormatCode}}, args...)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var (
		next []string
		oids []uint32
		n    int
	)
	for rows.Next() {
		if oids == nil {
			fds := rows.FieldDescriptions()
			oids = make([]uint32, len(fds))
			for i, fd := range fds {
				oids[i] = fd.DataTypeOID
			}
		}
		raw := rows.RawValues()
		next = next[:0]
		for i := range p.keyCols {
			next = append(next, string(raw[i]))
		}
		for i := range len(raw) - p.keyCols {
			j := p.keyCols + i
			if raw[j] == nil {
				continue
			}
			if err := value(i, readValue(oids[j], raw[j])); err != nil {
				return nil, 0, err
			}
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return next, n, nil
}

// readValue is a text-format value as the read path hands it: json and
// jsonb as json.RawMessage (the read path decodes them as JSON), every
// other type as its text. It copies raw, which the driver reuses.
func readValue(typeOID uint32, raw []byte) any {
	if typeOID == pgtype.JSONOID || typeOID == pgtype.JSONBOID {
		return json.RawMessage(bytes.Clone(raw))
	}
	return string(raw)
}
