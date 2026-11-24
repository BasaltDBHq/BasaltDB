// Package agentstore holds the types the agent's store ports are written in:
// the request the agent sends and what describe reads of a store, in words
// that fit any store. The store's
// adapter fills them; the agent service decides what is hidden and passes
// the rest on. Types only.
package agentstore

import "github.com/basaltdbhq/basaltdb/internal/core/action"

// Family is a family of stores that the agent reaches with the same tools.
// It picks the tool set the agent is served; the zero value is a store whose
// family has no tools yet.
type Family string

// FamilySQL is the stores that speak SQL (Postgres): the query and write
// tools, with the sql argument.
const FamilySQL Family = "SQL"

// Request is one request in the store's language: its text and its
// parameters. The agent service passes it on and records it, and never reads
// Text. Postgres: SQL text with $n parameters.
type Request struct {
	Text   string
	Params []any
}

// ResourceRef names one resource (a table, a collection, a bucket) as its
// store assigns it. It is opaque to the agent service: compared and used as
// a map key, never parsed. Postgres: the table's OID, as "16384".
type ResourceRef string

// FieldRef names one field of a resource as its store assigns it. It is
// opaque to the agent service. Postgres: the OID and attribute number, as
// "16384/3".
type FieldRef string

// Resource is one resource the agent can read.
type Resource struct {
	Ref ResourceRef
	// Namespace holds the resource: a Postgres schema.
	Namespace string
	Name      string
	// Kind is the store's kind of resource, as describe prints it: TABLE,
	// VIEW, MATERIALIZED_VIEW or PARTITIONED_TABLE for Postgres.
	Kind string
	// Estimate is the estimated number of rows or items, nil when the store
	// has none.
	Estimate *int64
	// Comment is the store's text about the resource, untrimmed.
	Comment string
	// Actions are what the agent may do to it: SELECT, INSERT, UPDATE and
	// DELETE.
	Actions []action.Op
}

// Field is one field of a resource. Readable is false so the service can
// count what it hides; it never shows such a field.
type Field struct {
	Ref FieldRef
	// Name and Type are the store's own name and type text.
	Name     string
	Type     string
	Nullable bool
	Comment  string
	Readable bool
	// ReadsFrom are the fields a default or computed value reads.
	ReadsFrom []FieldRef
	// Display is what the store shows of the field beyond its name, type
	// and nullability: a JSON-ready value that encodes to an object, or nil.
	// It may name the fields in ReadsFrom.
	Display any
	// Masked is shown in place of Display when a field in ReadsFrom is
	// hidden: a JSON-ready object, or nil, that names no other field.
	Masked any
}

// Feature is something of a resource built over its fields: an index, a
// foreign key.
type Feature struct {
	// Group is the answer's key the feature is listed under: "indexes".
	Group string
	// Touches are every field the feature uses. The feature is hidden, and
	// counted, when one of them is.
	Touches []FieldRef
	// Visible is false when the feature points at something the agent
	// cannot read: it is hidden and counted.
	Visible bool
	// Display is what the agent sees of the feature, a JSON-ready value. It
	// names no field that is not in Touches.
	Display any
	// Stable is Display without what changes with use (sizes, counters),
	// for the fingerprint; nil when Display has nothing of that kind.
	Stable any
}

// Detail is everything describe reports about one resource.
type Detail struct {
	Resource
	Fields []Field
	// Identity are the fields that identify an item: the primary key.
	Identity []FieldRef
	// Groups are the feature groups the store lists, in answer order; each
	// is listed even when it has no feature.
	Groups   []string
	Features []Feature
	// Stats are the store's figures on the resource, a JSON-ready value left
	// out of the fingerprint; nil when it has none.
	Stats any
	// Flags are store facts the answer carries as they are, by key: rls and
	// cascadesIntoHidden for Postgres.
	Flags map[string]any
}

// Match is one resource a search found.
type Match struct {
	Resource
	// Rank orders the matches, lowest first.
	Rank int
	// Matched says what matched: "table", "schema", "column <name>" or
	// "comment".
	Matched string
}

// Cursor is the last match of a search page; the next page starts after
// it.
type Cursor struct {
	Rank      int
	Namespace string
	Name      string
}
