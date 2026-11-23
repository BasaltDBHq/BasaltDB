package pii

import (
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// PiidictQuerier is the connection, pool or transaction the dictionary
// reads and the scanner run statements with, as the agent, seen through
// driver-free types (pgquerier.Port). A pgx handle is handed over through
// pgquerier.Neutralize.
type PiidictQuerier = pgquerier.Port
