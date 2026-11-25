package pii

import (
	"github.com/basaltdbhq/basaltdb/internal/lib/sqlport"
)

// PiidictQuerier is the pool the scanner runs its catalog reads with, as
// the agent, seen through driver-free types (sqlport.Port). A pgx handle is
// handed over through pgquerier.Neutralize.
type PiidictQuerier = sqlport.Port
