package pgpii

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// textTypes are the sampled text-like types (format_type spelling, without
// a schema).
var textTypes = map[string]bool{
	"text": true, "character varying": true, "character": true, "citext": true,
	"jsonb": true, "json": true, "name": true, `"char"`: true,
}

var intTypes = map[string]bool{"smallint": true, "integer": true, "bigint": true}

var dateTypes = map[string]bool{
	"date": true, "timestamp without time zone": true, "timestamp with time zone": true,
}

// KindOf maps a Postgres data type (format_type without modifier) to the
// classifier's kind. An array of a text-like type is text: it is sampled as
// its text form.
//
// The adapter rule: Postgres keeps this mapping, where a type it cannot
// place is piistore.KindOther (not sampled). A new store's adapter maps a
// type it cannot place, or a field holding mixed types, to piistore.KindText
// instead, so its values are sampled.
func KindOf(dataType string) piistore.Kind {
	t := dataType
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		t = t[i+1:] // a type in another schema: extensions.citext
	}
	t = strings.TrimSuffix(t, "[]")
	switch {
	case textTypes[t]:
		return piistore.KindText
	case strings.HasSuffix(dataType, "[]"):
		return piistore.KindOther
	case intTypes[t]:
		return piistore.KindInt
	case t == "numeric":
		return piistore.KindNumeric
	case dateTypes[t]:
		return piistore.KindDate
	case t == "boolean":
		return piistore.KindBool
	}
	return piistore.KindOther
}
