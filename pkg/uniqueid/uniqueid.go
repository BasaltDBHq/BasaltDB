package uniqueid

import "github.com/google/uuid"

// New returns a new UUIDv7 as canonical lowercase text for the wire and for
// SQLite TEXT id columns (16-byte BLOB storage is planned; text is canonical).
func New() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic("uuid.NewV7: " + err.Error())
	}
	return id.String()
}
