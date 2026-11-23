package pii

import (
	"github.com/basaltdbhq/basaltdb/internal/lib/sqlport"
)

// PiidictQuerier is the connection, pool or transaction the dictionary
// reads and the scanner run statements with, as the agent, seen through
// driver-free types (sqlport.Port). A pgx handle is handed over through
// pgquerier.Neutralize.
type PiidictQuerier = sqlport.Port
