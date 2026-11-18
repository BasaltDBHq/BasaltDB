package action

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Column is one result column.
type Column struct {
	Name string
	// Type is the store's type name, or "oid:<n>" for a Postgres type the
	// driver does not know.
	Type string
	// TableOID and Attnum are the table column the value comes from, both 0
	// for a computed column. The engine maps them to the column's PII
	// class; they never reach the agent.
	TableOID uint32
	Attnum   int16
}

// RowVersion is the version of one row a read saw.
type RowVersion struct {
	TableOID uint32
	// Key is a JSON object of the table's primary-key columns.
	Key     json.RawMessage
	Version string
}

// ReadResult is the rows of one read.
type ReadResult struct {
	Columns  []Column
	Rows     []map[string]any
	Duration time.Duration
	// Versions are the guarded rows the read saw, by key and version
	// (recorded reads); empty when no row could be identified.
	Versions []RowVersion
}

// Read is one read the engine ran for the agent, to record.
type Read struct {
	// RunID is uuid.Nil for a read outside a run.
	RunID     uuid.UUID
	Statement string
	Params    []any
	Tables    []string
	Rows      int
	Duration  time.Duration
	// Versions are the rows the engine could identify; empty for
	// aggregates and other statements without row identity.
	Versions []RowVersion
}

// Limits are the read limits the agent's statements run within.
type Limits struct {
	// StatementTimeout is the time limit of every agent transaction.
	StatementTimeout time.Duration
	// ReadRowLimit is the most rows a query may return.
	ReadRowLimit int
}
