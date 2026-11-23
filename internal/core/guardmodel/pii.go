package guardmodel

import "time"

// PII classes (CONTRACT.md, PII classification).
const (
	ClassPublic       = "PUBLIC"
	ClassIdentifier   = "IDENTIFIER"
	ClassFreeText     = "FREE_TEXT"
	ClassSecret       = "SECRET"
	ClassUnclassified = "UNCLASSIFIED"
)

// Entity types of an IDENTIFIER column.
const (
	EntityEmail      = "EMAIL"
	EntityPhone      = "PHONE"
	EntityPersonName = "PERSON_NAME"
	EntityAddress    = "ADDRESS"
	EntityOther      = "OTHER"
)

// PIIColumn is one row of basalt_meta.pii_columns that basalt classify
// writes. Empty strings are stored as NULL. A column of any class but
// UNCLASSIFIED is stamped confirmed by the login role at Classification.At.
type PIIColumn struct {
	Schema, Table, Column string
	// DataType is format_type without the modifier, as
	// pii_readable_columns() reports it.
	DataType            string
	Class               string
	EntityType          string
	SuggestedClass      string
	SuggestedEntityType string
	// Reason holds names and counts only, never a value.
	Reason      string
	NeedsReview bool
	PhoneRegion string
}

// Classification is one write of basalt classify.
type Classification struct {
	// Columns are upserted; columns not listed keep their row.
	Columns []PIIColumn
	// At stamps confirmed_at and classified_at.
	At time.Time
}

// ReadableColumn is one row of pii_readable_columns().
type ReadableColumn struct {
	TableOID              uint32
	Attnum                int16
	Schema, Table, Column string
	DataType              string
}

// ColumnKey names a column: schema, table and column.
type ColumnKey struct{ Schema, Table, Column string }

// ClassificationState is what basalt classify reads before it suggests:
// the readable columns, the stored classes and both fingerprints.
type ClassificationState struct {
	// Readable is pii_readable_columns(), by schema, table and attnum.
	Readable []ReadableColumn
	// Stored are the rows of pii_columns.
	Stored map[ColumnKey]PIIColumn
	// Fingerprint is pii_fingerprint() now.
	Fingerprint []byte
	// Previous is pii_catalog.fingerprint, nil before the first classify.
	Previous []byte
}

// Why a column needs a person (pii_unclassified().why).
const (
	UnclassifiedNew         = "NEW"
	UnclassifiedClass       = "UNCLASSIFIED"
	UnclassifiedTypeChanged = "TYPE_CHANGED"
)

// UnclassifiedColumn is one row of pii_unclassified(): a column the login
// role can read that needs a person.
type UnclassifiedColumn struct {
	Schema, Table, Column, DataType string
	// Why is UnclassifiedNew, UnclassifiedClass or UnclassifiedTypeChanged.
	Why string
}

// Name is schema.table.column.
func (c UnclassifiedColumn) Name() string { return c.Schema + "." + c.Table + "." + c.Column }

// Unclassified reports whether the column has no class yet (NEW or
// UNCLASSIFIED); a TYPE_CHANGED column keeps its class and needs a review.
func (c UnclassifiedColumn) Unclassified() bool {
	return c.Why == UnclassifiedNew || c.Why == UnclassifiedClass
}
