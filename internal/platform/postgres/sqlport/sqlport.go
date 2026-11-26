package sqlport

import (
	"context"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
)

type (
	Rows = interface {
		Close()
		Err() error
		Next() bool
		Scan(dest ...any) error
	}
	Row    = interface{ Scan(dest ...any) error }
	Result = interface{ RowsAffected() int64 }
)

type Port = interface {
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Builder builds the engine's own statements with Postgres placeholders.
var Builder = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// StatementTimeout is the call that sets statement_timeout to timeout, in
// whole milliseconds, for the current transaction only: transaction-local,
// so it cannot leak through a transaction pooler. A caller selects it
// alone (StatementTimeoutSQL) or beside the other settings it makes.
func StatementTimeout(timeout time.Duration) sq.Sqlizer {
	return sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", strconv.FormatInt(timeout.Milliseconds(), 10))
}

// StatementTimeoutSQL is the statement that sets statement_timeout to
// timeout for the current transaction only, for the caller to run on its
// transaction.
func StatementTimeoutSQL(timeout time.Duration) (string, []any, error) {
	return Builder.Select().Column(StatementTimeout(timeout)).ToSql()
}
