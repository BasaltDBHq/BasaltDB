package action

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ResourceRef names one resource (a table, a collection, a bucket) as its
// store assigns it. It is opaque outside the store's adapter: compared and
// used as a map key, never parsed. Postgres: "16384".
type ResourceRef string

// FieldRef names one field of a resource as its store assigns it. It is
// opaque outside the store's adapter. Postgres: "16384/3".
type FieldRef string

// Column is one result column.
type Column struct {
	Name string
	// Type is the store's type name; the store's adapter names a type it
	// does not know in its own words.
	Type string
	// Ref is the store field the value comes from, empty for a computed
	// column. The engine maps it to the field's PII class; it never reaches
	// the agent.
	Ref FieldRef
}

// RowVersion is the version of one row a read saw.
type RowVersion struct {
	// Resource is the resource the row is in.
	Resource ResourceRef
	// Key is a JSON object of the resource's key fields.
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
