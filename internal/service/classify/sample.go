package classify

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// maxValueChars bounds how much of one value is read: a sample is at most
// SampleRows values of this many characters, whatever the column holds.
const maxValueChars = 1024

// Why a sample could not be read (Sample.Unavailable).
const (
	UnavailableTimeout    = "timed out"
	UnavailableNoReadable = "not readable"
)

// SQLSTATEs a sample may fail with that leave the column unsampled instead
// of failing the run.
const (
	sqlStateQueryCanceled    = "57014"
	sqlStatePermissionDenied = "42501"
)

// KeyRef is a column by table oid and attribute number.
type KeyRef struct {
	TableOID uint32
	Attnum   int16
}

// KeyKind is what the catalog says of a column: part of a primary or
// foreign key, and/or filled by the database (identity or serial).
type KeyKind struct{ Key, Generated bool }

// KeyColumns lists the columns that are internal ids: part of a primary or
// foreign key, an identity column, or filled by a sequence (a serial's
// nextval default). Any role may read the catalog.
func KeyColumns(ctx context.Context, q Querier) (map[KeyRef]KeyKind, error) {
	// Plain SQL: a UNION over three catalogs, which squirrel cannot express.
	// Constant text, no arguments.
	rows, err := q.Query(ctx, `SELECT conrelid, unnest(conkey), false FROM pg_catalog.pg_constraint WHERE contype IN ('p', 'f')
		UNION
		SELECT attrelid, attnum, true FROM pg_catalog.pg_attribute WHERE attidentity <> '' AND attnum > 0 AND NOT attisdropped
		UNION
		SELECT adrelid, adnum, true FROM pg_catalog.pg_attrdef
		 WHERE pg_catalog.pg_get_expr(adbin, adrelid) LIKE 'nextval(%'`)
	if err != nil {
		return nil, fmt.Errorf("read key columns: %w", err)
	}
	out := map[KeyRef]KeyKind{}
	var (
		ref       KeyRef
		generated bool
	)
	_, err = pgx.ForEachRow(rows, []any{&ref.TableOID, &ref.Attnum, &generated}, func() error {
		k := out[ref]
		k.Generated = k.Generated || generated
		k.Key = k.Key || !generated
		out[ref] = k
		return nil
	})
	return out, err
}

// Sampler reads a bounded sample of a column's values as the admin:
// SampleRows non-null values, each cut to maxValueChars characters, in a
// read-only transaction under a statement timeout. The values are returned
// to the caller only; nothing is logged.
type Sampler struct {
	Conn    *pgx.Conn
	Timeout time.Duration
	// MaxChars cuts each value to this many characters; 0 means
	// maxValueChars.
	MaxChars int
}

// Sample reads col's sample. A sample that times out or that the admin may
// not read leaves the column unsampled (Sample.Unavailable); any other
// error fails.
func (s Sampler) Sample(ctx context.Context, col Column) (Sample, error) {
	ident := pgx.Identifier{col.Name}.Sanitize()
	maxChars := s.MaxChars
	if maxChars <= 0 {
		maxChars = maxValueChars
	}
	query, args, err := psql.Select(fmt.Sprintf("pg_catalog.left(%s::text, %d)", ident, maxChars)).
		From(pgx.Identifier{col.Schema, col.Table}.Sanitize()).
		Where(ident + " IS NOT NULL").
		Limit(SampleRows).ToSql()
	if err != nil {
		return Sample{}, err
	}
	var values []string
	err = readOnly(ctx, s.Conn, func(tx pgx.Tx) error {
		timeout := psql.Select().Column(sq.Expr("set_config('statement_timeout', ?, true)", strconv.FormatInt(s.Timeout.Milliseconds(), 10)))
		tsql, targs, err := timeout.ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, tsql, targs...); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		values, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err == nil {
		return Sample{Values: values}, nil
	}
	// A Postgres error's message and detail can quote a value (invalid
	// input syntax for type integer: "…"), so only its SQLSTATE is kept,
	// and the column is left for a person to review.
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return Sample{}, fmt.Errorf("sample %s: the connection failed", col.FullName())
	}
	switch pg.Code {
	case sqlStateQueryCanceled:
		return Sample{Unavailable: UnavailableTimeout}, nil
	case sqlStatePermissionDenied:
		return Sample{Unavailable: UnavailableNoReadable}, nil
	}
	return Sample{Unavailable: "error " + pg.Code}, nil
}

// readOnly runs fn in a read-only transaction that is always rolled back:
// a sample changes nothing, so nothing is committed.
func readOnly(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return fn(tx)
}

// BaseTypes maps every column whose type is a domain to the type the domain
// is built on, through domains of domains (format_type, no modifier), so a
// domain over text is sampled as text. Any role may read pg_catalog.
func BaseTypes(ctx context.Context, q Querier) (map[KeyRef]string, error) {
	// Plain SQL: a recursive CTE over the catalog, which squirrel cannot
	// express. Constant text, no arguments.
	rows, err := q.Query(ctx, `WITH RECURSIVE b(attrelid, attnum, typ) AS (
		SELECT a.attrelid, a.attnum, t.typbasetype
		  FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
		 WHERE t.typtype = 'd' AND a.attnum > 0 AND NOT a.attisdropped
		UNION ALL
		SELECT b.attrelid, b.attnum, t.typbasetype
		  FROM b JOIN pg_catalog.pg_type t ON t.oid = b.typ
		 WHERE t.typtype = 'd')
		SELECT b.attrelid, b.attnum, pg_catalog.format_type(b.typ, NULL)
		  FROM b JOIN pg_catalog.pg_type t ON t.oid = b.typ
		 WHERE t.typtype <> 'd'`)
	if err != nil {
		return nil, fmt.Errorf("read domain base types: %w", err)
	}
	out := map[KeyRef]string{}
	var (
		ref  KeyRef
		base string
	)
	_, err = pgx.ForEachRow(rows, []any{&ref.TableOID, &ref.Attnum, &base}, func() error {
		out[ref] = base
		return nil
	})
	return out, err
}
