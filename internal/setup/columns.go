package setup

import (
	"strings"
	"unicode"
)

// maxIdentifierBytes is Postgres's NAMEDATALEN - 1.
const maxIdentifierBytes = 63

// PlainColumn is a column name the engine passes on: not empty, at most 63
// bytes (a Postgres identifier), and no control character, which the local
// page's challenge separators could be confused with. It is checked before
// any connection is used.
func PlainColumn(name string) bool {
	return name != "" && len(name) <= maxIdentifierBytes && !strings.ContainsFunc(name, unicode.IsControl)
}
