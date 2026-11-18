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
