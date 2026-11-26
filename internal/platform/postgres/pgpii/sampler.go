package pgpii

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/lib/sqlident"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// maxValueChars bounds how much of one value is read: a sample is at most
// SampleRows values of this many characters, whatever the column holds.
const maxValueChars = 1024

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
func KeyColumns(ctx context.Context, q sqlport.Port) (map[KeyRef]KeyKind, error) {
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
	err = forEachSampleRow(rows, []any{&ref.TableOID, &ref.Attnum, &generated}, func() error {
		k := out[ref]
		k.Generated = k.Generated || generated
		k.Key = k.Key || !generated
		out[ref] = k
		return nil
	})
	return out, err
}

// ReadOnlyTx runs fn in a read-only transaction that is always rolled back
// (a sample changes nothing, so nothing is committed), and returns fn's
// error or the error of beginning it (pgquerier.ReadOnlyTx).
type ReadOnlyTx = func(ctx context.Context, fn func(sqlport.Port) error) error

// Sampler reads a bounded sample of a column's values as the admin:
// SampleRows non-null values, each cut to maxValueChars characters, in a
// read-only transaction under a statement timeout. The values are returned
// to the caller only; nothing is logged.
type Sampler struct {
	// ReadOnly runs a read-only transaction on the admin connection
	// (pgquerier.ReadOnlyTx).
	ReadOnly ReadOnlyTx
	Timeout  time.Duration
	// MaxChars cuts each value to this many characters; 0 means
	// maxValueChars.
	MaxChars int
}

// Sample reads col's sample. A sample that times out or that the admin may
// not read leaves the column unsampled (Sample.Unavailable); any other
// error fails.
func (s Sampler) Sample(ctx context.Context, col piistore.Column) (piistore.Sample, error) {
	ident := sqlident.Quote(col.Name)
	maxChars := s.MaxChars
	if maxChars <= 0 {
		maxChars = maxValueChars
	}
	query, args, err := sqlport.Builder.Select(fmt.Sprintf("pg_catalog.left(%s::text, %d)", ident, maxChars)).
		From(sqlident.Quote(col.Namespace, col.Resource)).
		Where(ident + " IS NOT NULL").
		Limit(piistore.SampleRows).ToSql()
	if err != nil {
		return piistore.Sample{}, err
	}
	var values []string
	err = s.ReadOnly(ctx, func(tx sqlport.Port) error {
		tsql, targs, err := sqlport.StatementTimeoutSQL(s.Timeout)
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
		values = []string{}
		var v string
		return forEachSampleRow(rows, []any{&v}, func() error {
			values = append(values, v)
			return nil
		})
	})
	if err == nil {
		return piistore.Sample{Values: values}, nil
	}
	// A Postgres error's message and detail can quote a value (invalid
	// input syntax for type integer: "…"), so only its SQLSTATE is kept,
	// and the column is left for a person to review.
	var pg sampleSQLStater
	if !errors.As(err, &pg) {
		return piistore.Sample{}, fmt.Errorf("sample %s: the connection failed", col.FullName())
	}
	code := pg.SQLState()
	switch code {
	case sqlStateQueryCanceled:
		return piistore.Sample{Unavailable: piistore.UnavailableTimeout}, nil
	case sqlStatePermissionDenied:
		return piistore.Sample{Unavailable: piistore.UnavailableNoReadable}, nil
	}
	return piistore.Sample{Unavailable: "error " + code}, nil
}

// sampleSQLStater is an error Postgres raised, with its SQLSTATE (the
// driver's error has this method).
type sampleSQLStater interface {
	error
	SQLState() string
}

// BaseTypes maps every column whose type is a domain to the type the domain
// is built on, through domains of domains (format_type, no modifier), so a
// domain over text is sampled as text. Any role may read pg_catalog.
func BaseTypes(ctx context.Context, q sqlport.Port) (map[KeyRef]string, error) {
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
	err = forEachSampleRow(rows, []any{&ref.TableOID, &ref.Attnum, &base}, func() error {
		out[ref] = base
		return nil
	})
	return out, err
}

// forEachSampleRow scans each row of rows into scans and calls fn after
// each, as pgx.ForEachRow does: it closes rows on return, and stops at the
// first error of Scan or fn, else returns the rows' error.
func forEachSampleRow(rows sqlport.Rows, scans []any, fn func() error) error {
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(scans...); err != nil {
			return err
		}
		if err := fn(); err != nil {
			return err
		}
	}
	return rows.Err()
}
