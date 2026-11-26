package piistore

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// FieldClass is the class of one field, as the store keeps it.
type FieldClass struct {
	// Ref is the field. Postgres: "<oid>/<attnum>".
	Ref action.FieldRef
	// Resource holds the field. Postgres: "<oid>".
	Resource action.ResourceRef
	// Namespace, ResourceName and Field are the printed names (never PII).
	Namespace, ResourceName, Field string
	Class                          string
	// EntityType is set exactly when Class is IDENTIFIER.
	EntityType string
	// PhoneRegion is the region a PHONE field's values are parsed in, or "".
	PhoneRegion string
}

// Marks are what a class map is loaded with: the live fingerprint of the
// fields the agent can read, and the fingerprint and time of the last
// classify (none before the first one). A change in either reloads the map.
type Marks struct {
	Fingerprint  []byte
	CatalogPrint []byte
	ClassifiedAt *time.Time
}

// Snapshot is one consistent read of the classes: the marks are read before
// the classes, so a classify that lands between the two leaves older marks,
// and the next check reloads. Fields are in the store's order.
type Snapshot struct {
	Marks  Marks
	Fields []FieldClass
}

// Unclassified is one field the agent can read that needs a person.
type Unclassified struct {
	// Name is the field's printed name, namespace.resource.field.
	Name string
	// DataType is the store's type, shown to the person only.
	DataType string
	// Changed is a field that keeps its class but changed type since it was
	// labeled; otherwise it has no class yet.
	Changed bool
}

// ResultField is one field of a result the agent is about to get: the field
// it comes from and its key in each row. An empty Ref is a computed value
// with no source field: it has no class.
type ResultField struct {
	Ref action.FieldRef
	Key string
}
