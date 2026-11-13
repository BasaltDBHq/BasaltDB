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

// Token-only entity types (owner decisions, PT-9, provisional). A column is
// never classified with them: a card or IBAN column is SECRET or OTHER. They
// exist so a card or an IBAN gets one token however it is spaced: the card
// and IBAN patterns emit them, and an OTHER value that is a valid card or IBAN
// is tokenized as one (tokenType).
const (
	EntityCard EntityType = "CARD"
	EntityIBAN EntityType = "IBAN"
)

// entityTypes are the column entity types, in contract order. The dictionary
// keeps one filter per type here.
var entityTypes = []EntityType{EntityEmail, EntityPhone, EntityPersonName, EntityAddress, EntityOther}

// tokenTypes are every type a span or a token may have: the column types,
// then the token-only types.
var tokenTypes = append(slices.Clone(entityTypes), EntityCard, EntityIBAN)

// TokenTypes lists every type a token may have: the column entity types in
// contract order (EMAIL, PHONE, PERSON_NAME, ADDRESS, OTHER), then CARD and IBAN.
func TokenTypes() []EntityType { return slices.Clone(tokenTypes) }

// Valid reports whether t is a type a span or a token may have.
func (t EntityType) Valid() bool { return slices.Contains(tokenTypes, t) }
