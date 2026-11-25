package piistore

// Kind is how the classifier treats a field's values. It is Basalt's word;
// the store's own type name is Column.DataType, for display only. The
// store's adapter maps its types to a Kind.
type Kind int

const (
	KindOther   Kind = iota // anything else: ids, bytes, arrays of non-text, …
	KindText                // text-like, sampled
	KindInt                 // integers, sampled
	KindNumeric             // decimal numbers, sampled
	KindDate                // dates and timestamps
	KindBool                // booleans
)

// Column is a field the agents can read, as the classifier sees it.
type Column struct {
	// Namespace and Resource name the field's resource (for Postgres, the
	// schema and the table); Name is the field.
	Namespace, Resource, Name string
	// Kind is how its values are treated. For a type built on another (a
	// Postgres domain), the adapter gives the kind of the type it is built
	// on.
	Kind Kind
	// DataType is the store's name for the field's type, shown in a
	// reason and never matched.
	DataType string
	// Key is true when the field is part of a primary or foreign key.
	Key bool
	// Generated is true for a field the store fills (an identity column or
	// one filled by a sequence).
	Generated bool
}

// FullName is namespace.resource.field, the printed name.
func (c Column) FullName() string { return c.Namespace + "." + c.Resource + "." + c.Name }

// SampleRows is how many non-null values are sampled per field.
const SampleRows = 1000

// Why a sample could not be read (Sample.Unavailable).
const (
	UnavailableTimeout    = "timed out"
	UnavailableNoReadable = "not readable"
)

// Sample is what reading a field's values gave.
type Sample struct {
	// Values are up to SampleRows non-null values as text.
	Values []string
	// Unavailable says why no sample could be read ("" when one was):
	// it timed out, or the reader may not read it.
	Unavailable string
}
