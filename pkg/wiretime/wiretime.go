// Package wiretime rewrites timestamptz values to the wire format
// (CONTRACT.md, Wire format): RFC 3339 UTC with a Z suffix, fractional
// seconds kept when present. Postgres prints a timestamptz in the session's
// TimeZone, so the same instant looks different per session; this makes the
// value the same everywhere an agent sees it.
package wiretime

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// layout is RFC 3339 with fractional seconds when present: trailing zeros
// are dropped and a whole second has none.
const layout = "2006-01-02T15:04:05.999999999Z07:00"

// naive is the date and time part, which time.Parse checks for range.
const naive = "2006-01-02T15:04:05.999999999"

// postgresText matches Postgres's ISO text output of a timestamptz
// ("2026-11-12 14:08:04.513958+02") and jsonb's form of the same value
// ("2026-11-12T14:08:04.513958+02:00"). A value without an offset (a
// timestamp without time zone) or with a BC suffix does not match.
var postgresText = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)([+-])(\d{2})(?::(\d{2}))?(?::(\d{2}))?$`)

const (
	secondsPerMinute = 60
	secondsPerHour   = 3600
	minOffsetGroups  = 5 // whole match, date, time, sign, hours
)

// Text rewrites s when it is a timestamptz as Postgres prints it or as
// jsonb holds it, and reports whether it was one. Anything else, including
// "infinity", is returned as given.
func Text(s string) (string, bool) {
	m := postgresText.FindStringSubmatch(s)
	if len(m) < minOffsetGroups {
		return s, false
	}
	t, err := time.Parse(naive, m[1]+"T"+m[2])
	if err != nil {
		return s, false
	}
	offset := atoi(m[4])*secondsPerHour + atoi(m[5])*secondsPerMinute + atoi(m[6])
	if m[3] == "-" {
		offset = -offset
	}
	return t.Add(-time.Duration(offset) * time.Second).UTC().Format(layout), true
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s) // empty (an absent group) is 0
	return n
}

// Value rewrites every string in a JSON-decoded value (map, slice, string)
// that Text recognizes, in place for maps and slices, and returns it.
func Value(v any) any {
	switch x := v.(type) {
	case string:
		out, _ := Text(x)
		return out
	case map[string]any:
		for k, e := range x {
			x[k] = Value(e)
		}
	case []any:
		for i, e := range x {
			x[i] = Value(e)
		}
	}
	return v
}

// Map is Value for a decoded object; a nil map stays nil.
func Map(m map[string]any) map[string]any {
	for k, e := range m {
		m[k] = Value(e)
	}
	return m
}

// JSON rewrites the timestamptz strings inside raw JSON. Numbers keep their
// exact spelling; raw is returned untouched when nothing changed or it does
// not parse.
func JSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	if !changed(v) {
		return raw
	}
	v = Value(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}

// changed reports whether Value would rewrite anything in v.
func changed(v any) bool {
	switch x := v.(type) {
	case string:
		_, ok := Text(x)
		return ok
	case map[string]any:
		for _, e := range x {
			if changed(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if changed(e) {
				return true
			}
		}
	}
	return false
}
