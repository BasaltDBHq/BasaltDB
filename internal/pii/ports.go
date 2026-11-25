package pii

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/lib/sqlport"
)

// Querier is the connection, pool or transaction the dictionary scan reads
// with, seen through driver-free types (sqlport.Port). A pgx handle is handed
// over through pgquerier.Neutralize.
type Querier = sqlport.Port

// Rows is a query's answer as this package reads it.
type Rows = sqlport.Rows

// ReadOnlyTx runs fn in a read-only transaction that is always rolled back
// (a read changes nothing, so nothing is committed), and returns fn's
// error or the error of beginning it.
type ReadOnlyTx = func(ctx context.Context, fn func(Querier) error) error

// forEachRow scans each row of rows into scans and calls fn after each, as
// pgx.ForEachRow does: it closes rows on return, and stops at the first
// error of Scan or fn, else returns the rows' error.
func forEachRow(rows Rows, scans []any, fn func() error) error {
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
