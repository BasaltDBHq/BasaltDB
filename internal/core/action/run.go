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

// The kinds of item list_runs returns.
const (
	RunItemRun        = "RUN"
	RunItemRevert     = "REVERT"
	RunItemLooseReads = "LOOSE_READS"
)

// RevertSummary is one revert the agent requested and the person signed
// (list_runs). Restored and Skipped are the rows restored and skipped so far.
type RevertSummary struct {
	ID       uuid.UUID
	Scope    string
	ScopeID  uuid.NullUUID
	SignedAt time.Time
	Restored int
	Skipped  int
	Intent   string
}

// LooseReads is the agent's reads made outside any run in one UTC hour, From
// inclusive to To exclusive (list_runs).
type LooseReads struct {
	From, To           time.Time
	Reads              int
	Resources          []string
	ResourcesTruncated bool
}

// RunListItem is one item of list_runs: a run, a revert, or one hour of
// reads outside a run, by Kind. Only the field of its kind is set. At is the
// time the list orders by: the run's start, the revert's signature, the
// start of the hour.
type RunListItem struct {
	Kind   string
	At     time.Time
	Run    RunSummary
	Revert RevertSummary
	Loose  LooseReads
}

// History is one page of a run's change records (C) with the rows each
// wrote (R), by change id. The record types are the ledger's: History only
// pairs them.
type History[C, R any] struct {
	Page pagination.Page[C]
	Rows map[uuid.UUID][]R
}
