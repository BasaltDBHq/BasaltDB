// Package uniqueid makes the ids BasaltDB generates: UUIDv7 in canonical text
// form. A UUIDv7 starts with a timestamp, so ids sort by creation time, which
// is why a list cursor can be the id alone.
package uniqueid

import "github.com/google/uuid"

// New returns a new UUIDv7 as canonical lowercase text for the wire and for
// Postgres text id columns (16-byte storage is a possible later change; text is canonical).
// New returns a new UUIDv7 as text. It panics if the system cannot supply
// random bytes, which no caller can recover from.
func New() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic("uuid.NewV7: " + err.Error())
	}
	return id.String()
}

// NewUUID returns a new UUIDv7, or the error when the system cannot supply
// random bytes.
func NewUUID() (uuid.UUID, error) {
	return uuid.NewV7()
}

// NewRandom returns a new UUIDv4: for an id that must not reveal when it was
// made, such as a plugin upload's. It panics if the system cannot supply
// random bytes.
func NewRandom() uuid.UUID {
	return uuid.New()
}

// Optional parses an optional uuid argument already validated by its tags: ""
// is uuid.Nil.
func Optional(s string) uuid.UUID {
	if s == "" {
		return uuid.Nil
	}
	return uuid.MustParse(s)
}
