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

	"github.com/basaltdbhq/basaltdb/internal/guard"
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

// KeyColumns lists the columns that are part of a primary or foreign key.
// Any role may read pg_constraint.
func KeyColumns(ctx context.Context, q guard.Querier) (map[KeyRef]bool, error) {
	sql, args, err := psql.Select("conrelid", "unnest(conkey)").From("pg_catalog.pg_constraint").
		Where(sq.Eq{"contype": []string{"p", "f"}}).ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("read key columns: %w", err)
	}
	out := map[KeyRef]bool{}
	var ref KeyRef
	_, err = pgx.ForEachRow(rows, []any{&ref.TableOID, &ref.Attnum}, func() error {
		out[ref] = true
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
}

// Sample reads col's sample. A sample that times out or that the admin may
// not read leaves the column unsampled (Sample.Unavailable); any other
// error fails.
func (s Sampler) Sample(ctx context.Context, col Column) (Sample, error) {
	ident := pgx.Identifier{col.Name}.Sanitize()
	query, args, err := psql.Select(fmt.Sprintf("left(%s::text, %d)", ident, maxValueChars)).
		From(pgx.Identifier{col.Schema, col.Table}.Sanitize()).
		Where(ident + " IS NOT NULL").
		Limit(SampleRows).ToSql()
	if err != nil {
		return Sample{}, err
	}
	var values []string
	err = pgx.BeginTxFunc(ctx, s.Conn, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
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
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return Sample{Values: values}, nil
	case errors.As(err, &pg) && pg.Code == sqlStateQueryCanceled:
		return Sample{Unavailable: UnavailableTimeout}, nil
	case errors.As(err, &pg) && pg.Code == sqlStatePermissionDenied:
		return Sample{Unavailable: UnavailableNoReadable}, nil
	}
	return Sample{}, fmt.Errorf("sample %s: %w", col.FullName(), err)
}
