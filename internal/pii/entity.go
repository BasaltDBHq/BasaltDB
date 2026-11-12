package pii

import "slices"

// EntityType is the kind of an IDENTIFIER value (CONTRACT.md, Entity types).
// Each type has its own token key, so equal text of two types gets two tokens.
type EntityType string

// Entity types, as on the wire and in basalt_meta.
const (
	EntityEmail      EntityType = "EMAIL"
	EntityPhone      EntityType = "PHONE"
	EntityPersonName EntityType = "PERSON_NAME"
	EntityAddress    EntityType = "ADDRESS"
	EntityOther      EntityType = "OTHER"
)

var entityTypes = []EntityType{EntityEmail, EntityPhone, EntityPersonName, EntityAddress, EntityOther}

// EntityTypes lists every entity type in contract order.
func EntityTypes() []EntityType { return slices.Clone(entityTypes) }

// Valid reports whether t is one of the entity types.
func (t EntityType) Valid() bool { return slices.Contains(entityTypes, t) }
