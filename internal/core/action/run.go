package action

import (
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Run is one of the agent's runs.
type Run struct {
	ID     uuid.UUID
	TaskID uuid.UUID // uuid.Nil when the run has no task
	Intent string
}

// RunSummary is one of the agent's runs with what it did (list_runs).
type RunSummary struct {
	ID        uuid.UUID
	TaskID    uuid.NullUUID
	Intent    string
	StartedAt time.Time
	// LastChangeAt is the run's latest change record, nil when it has none.
	LastChangeAt *time.Time
	Applied      int
	Held         int
	Refused      int
	Reverted     int
	Reads        int
	RowsWritten  int
	// Resources the run wrote to, in the store's form and name order, at
	// most the store's limit.
	Resources          []string
	ResourcesTruncated bool
}

// History is one page of a run's change records (C) with the rows each
// wrote (R), by change id. The record types are the ledger's: History only
// pairs them.
type History[C, R any] struct {
	Page pagination.Page[C]
	Rows map[uuid.UUID][]R
}
