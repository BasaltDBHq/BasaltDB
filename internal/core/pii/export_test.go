package pii

import "slices"

// TokenTypes lists every type a token may have: the column entity types in
// contract order (EMAIL, PHONE, PERSON_NAME, ADDRESS, OTHER), then CARD and IBAN.
func TokenTypes() []EntityType { return slices.Clone(tokenTypes) }
