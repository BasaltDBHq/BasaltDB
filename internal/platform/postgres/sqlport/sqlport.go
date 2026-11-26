// Package sqlport is the driver-free shape of a Postgres handle: the query
// port a service declares for itself (setup's Querier), with no driver type
// in it. A package that names these types links no database driver; a pgx
// handle is handed over through pgquerier.
package sqlport

import "context"

// Rows, Row and Result are the answers of a driver-free query, written as
// unnamed interfaces so every package's types of the same shape are the same
// types.
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

// Port is the driver-free query port a service declares for itself (setuprun
// Querier): the same interface, so pgquerier.Neutral implements it and so does
// anything else of the same shape.
type Port = interface {
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}
