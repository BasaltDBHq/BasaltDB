package setup

import (
	"strings"
	"unicode"
)

// maxIdentifierBytes is Postgres's NAMEDATALEN - 1.
const maxIdentifierBytes = 63

// PlainColumn is a column name the engine passes on: not empty, at most 63
// bytes (a Postgres identifier), and no control character, which the local
// page's challenge separators could be confused with. pkg/setup.Run checks
// it before it reads the database; the local setup page checks it with the
// install's labels before it connects, and with an Update check's labels
// in the LABELS fix.
func PlainColumn(name string) bool {
	return name != "" && len(name) <= maxIdentifierBytes && !strings.ContainsFunc(name, unicode.IsControl)
}
