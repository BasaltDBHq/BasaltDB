package guardmodel

import (
	"errors"
	"slices"
)

// Label is a column's class as the connect page shows and sets it.
type Label struct {
	Class, EntityType, PhoneRegion string
}

// ColumnLabel is one column of a table and its class now.
type ColumnLabel struct {
	// Table is schema.table.
	Table, Column string
	Label
}

// LabelChange is a class the person set on a column, with the class it had
// when it was shown (Was).
type LabelChange struct {
	Table, Column string
	Label
	Was Label
}

// ErrClassesChanged is a change whose column's class stored now is not its
// Was, or whose column is gone: someone classified or changed the table
// since the person saw it. Nothing is written.
var ErrClassesChanged = errors.New("a column's class or the column itself changed since it was shown")

// labelClasses are the classes the connect page sets.
var labelClasses = []string{ClassPublic, ClassIdentifier, ClassSecret}

// entityTypes are the entity types of an IDENTIFIER column.
var entityTypes = []string{EntityEmail, EntityPhone, EntityPersonName, EntityAddress, EntityOther}

// ValidLabel reports whether l is a class the connect page may set:
// PUBLIC, IDENTIFIER with an entity type, or SECRET; a phone region, upper
// case ISO 3166-1 alpha-2, with PHONE only and required there.
func ValidLabel(l Label) bool {
	return slices.Contains(labelClasses, l.Class) && validEntity(l, true)
}

// ValidWas reports whether l is a class a column can have now: any of the
// five, with the same entity type rule, and a region with PHONE only, when
// one is stored.
func ValidWas(l Label) bool {
	return slices.Contains([]string{ClassPublic, ClassIdentifier, ClassFreeText, ClassSecret, ClassUnclassified}, l.Class) && validEntity(l, false)
}

func validEntity(l Label, regionRequired bool) bool {
	if l.Class != ClassIdentifier {
		return l.EntityType == "" && l.PhoneRegion == ""
	}
	if !slices.Contains(entityTypes, l.EntityType) {
		return false
	}
	if l.EntityType != EntityPhone {
		return l.PhoneRegion == ""
	}
	if l.PhoneRegion == "" && !regionRequired {
		return true
	}
	return len(l.PhoneRegion) == 2 && l.PhoneRegion[0] >= 'A' && l.PhoneRegion[0] <= 'Z' && l.PhoneRegion[1] >= 'A' && l.PhoneRegion[1] <= 'Z'
}
