package pii

import (
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// Querier is the connection, pool or transaction a sample is read with,
// seen through driver-free types (pgquerier.Port). A pgx handle is handed
// over through pgquerier.Neutralize.
type Querier = pgquerier.Port

// Rows is a query's answer as this package reads it.
type Rows = pgquerier.Rows

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
