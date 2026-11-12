package classify

import "strings"

// kind is what the classifier makes of a column's data type.
type kind int

const (
	kindOther   kind = iota // anything else: uuid, bytea, arrays of non-text, …
	kindText                // text-like, sampled
	kindInt                 // integers, sampled
	kindNumeric             // numeric, sampled
	kindDate                // dates and timestamps
	kindBool                // boolean
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

// kindOf maps a data type (format_type without modifier) to its kind. An
// array of a text-like type is text: it is sampled as its text form.
func kindOf(dataType string) kind {
	t := dataType
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		t = t[i+1:] // a type in another schema: extensions.citext
	}
	t = strings.TrimSuffix(t, "[]")
	switch {
	case textTypes[t]:
		return kindText
	case strings.HasSuffix(dataType, "[]"):
		return kindOther
	case intTypes[t]:
		return kindInt
	case t == "numeric":
		return kindNumeric
	case dateTypes[t]:
		return kindDate
	case t == "boolean":
		return kindBool
	}
	return kindOther
}

// Sampled reports whether basalt classify samples a column of this data
// type: text-like, integer and numeric types.
func Sampled(dataType string) bool {
	switch kindOf(dataType) {
	case kindText, kindInt, kindNumeric:
		return true
	case kindOther, kindDate, kindBool:
	}
	return false
}
