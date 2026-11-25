package pii

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// Column is a field the agents can read, as the classifier sees it.
type Column = piistore.Column

// Sample is what reading a field's values gave.
type Sample = piistore.Sample

// SampleRows is how many non-null values are sampled per field.
const SampleRows = piistore.SampleRows

// Why a sample could not be read (Sample.Unavailable).
const (
	UnavailableTimeout    = piistore.UnavailableTimeout
	UnavailableNoReadable = piistore.UnavailableNoReadable
)

// sqlStater is an error Postgres raised, with its SQLSTATE (the driver's
// error has this method). The dictionary scan reads it until its reader
// moves to the store's adapter.
type sqlStater interface {
	error
	SQLState() string
}

// quoteIdentifier is the identifier of parts (schema, table or column),
// each double-quoted with its quotes doubled and any NUL dropped, joined by
// dots: what the driver's Identifier.Sanitize writes. The dictionary scan
// uses it until its reader moves to the store's adapter.
func quoteIdentifier(parts ...string) string {
	quoted := make([]string, len(parts))
	for i, p := range parts {
		p = strings.ReplaceAll(p, "\x00", "")
		quoted[i] = `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
	}
	return strings.Join(quoted, ".")
}
