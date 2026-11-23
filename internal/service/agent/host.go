package agent

import (
	"time"
)

// The catalog's own types: what describe reads of the database's tables
// and views.

// CatalogRelation is one table, view, materialized view or partitioned
// table the session's role can read. Partitions are never listed on their
// own.
type CatalogRelation struct {
	OID    uint32
	Schema string
	Name   string
	// Kind is TABLE, VIEW, MATERIALIZED_VIEW or PARTITIONED_TABLE.
	Kind string
	// EstimatedRows is nil when the relation was never analyzed.
	EstimatedRows *int64
	// Comment is the catalog text, untrimmed.
	Comment string
	// Privileges lists SELECT, INSERT, UPDATE and DELETE as held by
	// session_user.
	Privileges []string
}

// CatalogColumn is one column of a relation. Selectable is false so the
// caller can count what it hides; it must not show them.
type CatalogColumn struct {
	Attnum int16
	Name   string
	// Type is the text format_type prints.
	Type     string
	Nullable bool
	// Default is the pg_get_expr text, empty when there is none.
	Default string
	// DefaultAttnums are the columns the default or generated expression reads.
	DefaultAttnums []int16
	Generated      bool
	Comment        string
	// Selectable is has_column_privilege(session_user, ..., 'SELECT').
	Selectable bool
}

// CatalogIndex is one index of a relation.
type CatalogIndex struct {
	Name       string
	Definition string
	// Attnums are the key and INCLUDE columns plus the columns read by
	// expressions and the predicate.
	Attnums   []int16
	Unique    bool
	Partial   bool
	SizeBytes int64
	Scans     int64
}

// CatalogKey is one foreign key touching a relation, seen from that
// relation.
type CatalogKey struct {
	Name     string
	Outgoing bool
	// Attnums are the key columns on this relation.
	Attnums  []int16
	OtherOID uint32
	// OtherSchema, OtherTable and OtherColumns are empty when the other
	// relation is not readable by session_user: a hidden table is counted,
	// never named.
	OtherSchema   string
	OtherTable    string
	OtherColumns  []string
	OtherReadable bool
	// OnDelete and OnUpdate are CASCADE, SET NULL, SET DEFAULT, RESTRICT or
	// NO ACTION.
	OnDelete string
	OnUpdate string
}

// CatalogStats is the size and scan activity of a relation. LastAnalyzed is
// nil when it never was.
type CatalogStats struct {
	TableBytes   int64
	TotalBytes   int64
	SeqScans     int64
	IndexScans   int64
	LastAnalyzed *time.Time
}

// CatalogDetail is everything describe reports about one relation.
type CatalogDetail struct {
	CatalogRelation
	Columns    []CatalogColumn
	PrimaryKey []int16
	Indexes    []CatalogIndex
	Keys       []CatalogKey
	Stats      CatalogStats
	RLS        bool
	// CascadesIntoHidden is how many distinct unreadable tables a DELETE here
	// reaches, transitively over CASCADE, SET NULL and SET DEFAULT.
	CascadesIntoHidden int
}

// CatalogMatch is one relation a search matched.
type CatalogMatch struct {
	CatalogRelation
	Rank int
	// Matched is "table", "schema", "column <name>" or "comment".
	Matched string
}

// CatalogSearchCursor is the last match of a page; the next page starts
// after it.
type CatalogSearchCursor struct {
	Rank   int
	Schema string
	Name   string
}

// CatalogColumnKey names one column by table OID and attribute number.
type CatalogColumnKey struct {
	OID    uint32
	Attnum int16
}
