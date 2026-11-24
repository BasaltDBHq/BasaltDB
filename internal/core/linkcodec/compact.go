package linkcodec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

const (
	// MaxLinesBytes caps the rebuilt lines, in UTF-8 bytes summed over the
	// lines, so a small link cannot rebuild into a large page.
	MaxLinesBytes = 1 << 20
	// maxEntries caps a shape's top-level keys: a preview line has 6 and a
	// revert line 10.
	maxEntries = 64
	// maxColumns caps an object entry's columns: Postgres's
	// MaxHeapAttributeNumber.
	maxColumns = 1600
	// maxDepth caps how deep arrays nest inside one value.
	maxDepth = 32
	// maxSafeInteger is 2^53 - 1, the largest integer a JavaScript number
	// holds exactly (Number.MAX_SAFE_INTEGER).
	maxSafeInteger = 1<<53 - 1
	// MaxCredentialIDs caps the credential ids a link carries: the bound
	// the relays read the database's passkeys with.
	MaxCredentialIDs = 100
	// withCredentialIDs is the length of [shapes, lines, credentialIds].
	withCredentialIDs = 3
	// maxCredentialID is WebAuthn's longest credential id, in bytes.
	maxCredentialID = 1023
)

// Lines is format 2's compact form of a request's texts (CONTRACT.md,
// Codes, Format 2): the binding text, then the lines. Each text is either
// itself, or a shape and that shape's values; the shapes are the distinct
// key layouts of the texts, each listed once. JSON: [shapes, lines], or
// [shapes, lines, credentialIds] when the link names the database's
// passkeys: the page passes them as allowCredentials, so the browser offers
// only those. They are not signed; Postgres still checks the passkey.
type Lines struct {
	Shapes        []Shape
	Lines         []Line
	CredentialIDs []passkey.Bytes
}

// MarshalJSON writes [shapes, lines], with the credential ids third when
// there are any.
func (c Lines) MarshalJSON() ([]byte, error) {
	shapes := c.Shapes
	if shapes == nil {
		shapes = []Shape{}
	}
	if len(c.CredentialIDs) > 0 {
		return Marshal([]any{shapes, c.Lines, c.CredentialIDs})
	}
	return Marshal([]any{shapes, c.Lines})
}

// UnmarshalJSON reads [shapes, lines], both arrays, and an optional third
// array of 1 to MaxCredentialIDs distinct credential ids.
func (c *Lines) UnmarshalJSON(raw []byte) error {
	var pair []json.RawMessage
	if first(raw) != '[' || json.Unmarshal(raw, &pair) != nil || len(pair) < 2 || len(pair) > withCredentialIDs || first(pair[0]) != '[' || first(pair[1]) != '[' {
		return errors.New("is not [shapes, lines] or [shapes, lines, credentialIds]")
	}
	*c = Lines{}
	if err := json.Unmarshal(pair[0], &c.Shapes); err != nil {
		return fmt.Errorf("shapes: %w", err)
	}
	if err := json.Unmarshal(pair[1], &c.Lines); err != nil {
		return fmt.Errorf("lines: %w", err)
	}
	if len(pair) == withCredentialIDs {
		ids, err := credentialIDs(pair[2])
		if err != nil {
			return fmt.Errorf("credentialIds: %w", err)
		}
		c.CredentialIDs = ids
	}
	return nil
}

// credentialIDs reads a link's credential ids: an array of 1 to
// MaxCredentialIDs distinct base64url ids of 1 to 1023 bytes.
func credentialIDs(raw json.RawMessage) ([]passkey.Bytes, error) {
	var ids []passkey.Bytes
	if first(raw) != '[' {
		return nil, errors.New("is not an array")
	}
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > MaxCredentialIDs {
		return nil, fmt.Errorf("has %d ids, want 1 to %d", len(ids), MaxCredentialIDs)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if len(id) == 0 || len(id) > maxCredentialID {
			return nil, fmt.Errorf("has an id of %d bytes, want 1 to %d", len(id), maxCredentialID)
		}
		if seen[string(id)] {
			return nil, errors.New("names an id twice")
		}
		seen[string(id)] = true
	}
	return ids, nil
}

// Shape is a line's top-level keys in text order.
type Shape []Entry

// Entry is one top-level key of a line. A key whose value is an object (key,
// old, set, now) lists that object's columns, and the line gives one value
// per column. JSON: "name", or ["name", ["column", ...]].
type Entry struct {
	Name    string
	Object  bool
	Columns []string
}

// Line is one line: its text as it is (Verbatim, for a line that does not
// rebuild exactly), or a shape index and one value per slot of that shape.
// JSON: "text", or [shape, value, ...].
type Line struct {
	Verbatim bool
	Text     string
	Shape    int
	Values   []json.RawMessage
}

// Compact returns the format 2 form of lines. A line that does not parse as
// a JSON object, or does not rebuild to exactly its text, travels as its
// text, so Rebuild always returns lines unchanged.
func Compact(lines []string) Lines {
	c := Lines{Shapes: []Shape{}, Lines: make([]Line, 0, len(lines))}
	index := map[string]int{}
	for _, text := range lines {
		c.Lines = append(c.Lines, c.compactLine(text, index))
	}
	return c
}

func (c *Lines) compactLine(text string, index map[string]int) Line {
	verbatim := Line{Verbatim: true, Text: text}
	shape, values, err := splitLine(text)
	if err != nil || shape.check() != nil {
		return verbatim
	}
	if rebuilt, err := shape.build(values, MaxLinesBytes); err != nil || rebuilt != text {
		return verbatim
	}
	key, err := json.Marshal(shape)
	if err != nil {
		return verbatim
	}
	i, ok := index[string(key)]
	if !ok {
		i = len(c.Shapes)
		c.Shapes = append(c.Shapes, shape)
		index[string(key)] = i
	}
	return Line{Shape: i, Values: values}
}

// Rebuild returns the lines' text: at least one and at most maxLines lines,
// every shape used, every line with exactly its shape's slots, and at most
// MaxLinesBytes in all.
func (c Lines) Rebuild(maxLines int) ([]string, error) {
	switch {
	case len(c.Lines) == 0:
		return nil, errors.New("has no lines")
	case len(c.Lines) > maxLines:
		return nil, fmt.Errorf("has %d lines, at most %d", len(c.Lines), maxLines)
	case len(c.Shapes) > len(c.Lines):
		return nil, fmt.Errorf("has %d shapes for %d lines", len(c.Shapes), len(c.Lines))
	}
	for i, s := range c.Shapes {
		if err := s.check(); err != nil {
			return nil, fmt.Errorf("shape %d: %w", i, err)
		}
	}
	used := make([]bool, len(c.Shapes))
	out := make([]string, 0, len(c.Lines))
	total := 0
	for i, l := range c.Lines {
		text, err := c.line(l, used, MaxLinesBytes-total)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i, err)
		}
		total += len(text)
		if total > MaxLinesBytes {
			return nil, errTooLong
		}
		out = append(out, text)
	}
	for i, u := range used {
		if !u {
			return nil, fmt.Errorf("shape %d is unused", i)
		}
	}
	return out, nil
}

var errTooLong = fmt.Errorf("lines rebuild past %d MiB", MaxLinesBytes>>20)

func (c Lines) line(l Line, used []bool, budget int) (string, error) {
	if l.Verbatim {
		return l.Text, nil
	}
	if l.Shape < 0 || l.Shape >= len(c.Shapes) {
		return "", fmt.Errorf("names shape %d of %d", l.Shape, len(c.Shapes))
	}
	used[l.Shape] = true
	return c.Shapes[l.Shape].build(l.Values, budget)
}

func (s Shape) check() error {
	if len(s) == 0 || len(s) > maxEntries {
		return fmt.Errorf("has %d entries, 1 to %d", len(s), maxEntries)
	}
	for _, e := range s {
		if len(e.Columns) > maxColumns {
			return fmt.Errorf("entry %q has %d columns, at most %d", e.Name, len(e.Columns), maxColumns)
		}
	}
	return nil
}

func (s Shape) slots() int {
	n := 0
	for _, e := range s {
		n++
		if e.Object {
			n += len(e.Columns) - 1
		}
	}
	return n
}

// build writes the line as Postgres's jsonb text does: `{"k": v, ...}`,
// object entries as `{"c": v, ...}`. It stops once the text passes budget
// bytes.
func (s Shape) build(values []json.RawMessage, budget int) (string, error) {
	if len(values) != s.slots() {
		return "", fmt.Errorf("has %d values, its shape %d", len(values), s.slots())
	}
	var b strings.Builder
	b.WriteByte('{')
	next := 0
	for i, e := range s {
		if i > 0 {
			b.WriteString(", ")
		}
		quote(&b, e.Name)
		b.WriteString(": ")
		if !e.Object {
			if err := emit(&b, values[next], 0); err != nil {
				return "", err
			}
			next++
		} else {
			if err := emitObject(&b, e.Columns, values[next:next+len(e.Columns)]); err != nil {
				return "", err
			}
			next += len(e.Columns)
		}
		if b.Len() > budget {
			return "", errTooLong
		}
	}
	b.WriteByte('}')
	return b.String(), nil
}

func emitObject(b *strings.Builder, columns []string, values []json.RawMessage) error {
	b.WriteByte('{')
	for i, col := range columns {
		if i > 0 {
			b.WriteString(", ")
		}
		quote(b, col)
		b.WriteString(": ")
		if err := emit(b, values[i], 0); err != nil {
			return fmt.Errorf("column %q: %w", col, err)
		}
	}
	b.WriteByte('}')
	return nil
}

// emit writes one value: a string as jsonb quotes it, true, false, null, a
// safe integer in decimal, an array of values, or {"raw": text} as text.
func emit(b *strings.Builder, raw json.RawMessage, depth int) error {
	switch first(raw) {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("value: %w", err)
		}
		quote(b, s)
	case 't', 'f', 'n':
		b.Write(bytes.TrimSpace(raw))
	case '[':
		return emitArray(b, raw, depth)
	case '{':
		text, err := rawText(raw)
		if err != nil {
			return err
		}
		b.WriteString(text)
	default:
		n, err := safeInteger(raw)
		if err != nil {
			return err
		}
		b.WriteString(strconv.FormatInt(n, 10))
	}
	return nil
}

func emitArray(b *strings.Builder, raw json.RawMessage, depth int) error {
	if depth >= maxDepth {
		return fmt.Errorf("value nests arrays deeper than %d", maxDepth)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("value: %w", err)
	}
	b.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := emit(b, item, depth+1); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

// rawText reads {"raw": "<text>"}, a value carried as its jsonb text.
func rawText(raw json.RawMessage) (string, error) {
	var tag map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tag); err != nil {
		return "", fmt.Errorf("value: %w", err)
	}
	text, ok := tag["raw"]
	if len(tag) != 1 || !ok {
		return "", errors.New(`an object value must be {"raw": text}`)
	}
	s, err := jsonString(text)
	if err != nil {
		return "", fmt.Errorf(`raw value: %w`, err)
	}
	return s, nil
}

// safeInteger reads a JSON number as JavaScript does (JSON.parse, so 1.0
// and 1e2 are integers) and accepts it only when it is an integer of at
// most 2^53 - 1 that is not -0, so Go and the pages rebuild the same text.
func safeInteger(raw json.RawMessage) (int64, error) {
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger || (f == 0 && math.Signbit(f)) {
		return 0, fmt.Errorf("value %.20s is not a safe integer", raw)
	}
	return int64(f), nil
}

// quote writes s as Postgres's escape_json does: \" \\ \b \f \n \r \t,
// other bytes below 0x20 as \u00xx, everything else as it is.
func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < ' ' {
				fmt.Fprintf(b, `\u%04x`, c)
				continue
			}
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// first returns the first byte of a JSON value, 0 for none.
func first(raw json.RawMessage) byte {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 {
		return 0
	}
	return raw[0]
}

// jsonString reads a JSON string, refusing null and every other type.
func jsonString(raw json.RawMessage) (string, error) {
	if first(raw) != '"' {
		return "", errors.New("not a string")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// MarshalJSON writes "name" or ["name", ["column", ...]].
func (e Entry) MarshalJSON() ([]byte, error) {
	if !e.Object {
		return Marshal(e.Name)
	}
	cols := e.Columns
	if cols == nil {
		cols = []string{}
	}
	return Marshal([]any{e.Name, cols})
}

// UnmarshalJSON reads "name" or ["name", ["column", ...]].
func (e *Entry) UnmarshalJSON(raw []byte) error {
	if first(raw) == '"' {
		name, err := jsonString(raw)
		*e = Entry{Name: name}
		return err
	}
	var pair []json.RawMessage
	if first(raw) != '[' || json.Unmarshal(raw, &pair) != nil || len(pair) != 2 || first(pair[1]) != '[' {
		return errors.New(`an entry is "name" or ["name", ["column", ...]]`)
	}
	name, err := jsonString(pair[0])
	if err != nil {
		return fmt.Errorf("entry name: %w", err)
	}
	var cols []json.RawMessage
	if err := json.Unmarshal(pair[1], &cols); err != nil {
		return fmt.Errorf("entry %q columns: %w", name, err)
	}
	*e = Entry{Name: name, Object: true, Columns: make([]string, 0, len(cols))}
	for _, c := range cols {
		col, err := jsonString(c)
		if err != nil {
			return fmt.Errorf("entry %q column: %w", name, err)
		}
		e.Columns = append(e.Columns, col)
	}
	return nil
}

// MarshalJSON writes "text" or [shape, value, ...].
func (l Line) MarshalJSON() ([]byte, error) {
	if l.Verbatim {
		return Marshal(l.Text)
	}
	items := make([]any, 0, len(l.Values)+1)
	items = append(items, l.Shape)
	for _, v := range l.Values {
		items = append(items, v)
	}
	return Marshal(items)
}

// UnmarshalJSON reads "text" or [shape, value, ...].
func (l *Line) UnmarshalJSON(raw []byte) error {
	if first(raw) == '"' {
		text, err := jsonString(raw)
		*l = Line{Verbatim: true, Text: text}
		return err
	}
	var items []json.RawMessage
	if first(raw) != '[' || json.Unmarshal(raw, &items) != nil || len(items) == 0 {
		return errors.New(`a line is "text" or [shape, value, ...]`)
	}
	shape, err := safeInteger(items[0])
	if err != nil {
		return errors.New("a line's shape is an index")
	}
	*l = Line{Shape: int(shape), Values: items[1:]}
	return nil
}

// splitLine reads a line printed by Postgres: an object whose values are
// scalars, arrays or objects. An object value becomes an object entry, with
// one value per column.
func splitLine(text string) (Shape, []json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	var shape Shape
	var values []json.RawMessage
	err := eachMember(dec, func(name string, raw json.RawMessage) error {
		if first(raw) != '{' {
			shape = append(shape, Entry{Name: name})
			values = append(values, compactValue(raw, 0))
			return nil
		}
		cols := []string{}
		err := eachMember(json.NewDecoder(bytes.NewReader(raw)), func(col string, v json.RawMessage) error {
			cols = append(cols, col)
			values = append(values, compactValue(v, 0))
			return nil
		})
		shape = append(shape, Entry{Name: name, Object: true, Columns: cols})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errTrailing
	}
	return shape, values, nil
}

// eachMember reads one JSON object from dec and calls fn for each member in
// text order.
func eachMember(dec *json.Decoder, fn func(name string, raw json.RawMessage) error) error {
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not an object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := tok.(string)
		if !ok {
			return errors.New("not an object key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if err := fn(name, raw); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// compactValue returns the format 2 value for a jsonb value: strings,
// true, false, null and canonical safe integers as they are, arrays element
// by element, and anything else (other numbers, objects, deep arrays) as
// {"raw": text}.
func compactValue(raw json.RawMessage, depth int) json.RawMessage {
	switch first(raw) {
	case '"', 't', 'f', 'n':
		return raw
	case '[':
		if depth >= maxDepth {
			return rawValue(raw)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return rawValue(raw)
		}
		for i, item := range items {
			items[i] = compactValue(item, depth+1)
		}
		out, err := Marshal(items)
		if err != nil {
			return rawValue(raw)
		}
		return out
	case '{':
		return rawValue(raw)
	default:
		if n, err := safeInteger(raw); err == nil && strconv.FormatInt(n, 10) == string(raw) {
			return raw
		}
		return rawValue(raw)
	}
}

func rawValue(raw json.RawMessage) json.RawMessage {
	out, err := Marshal(map[string]string{"raw": string(raw)})
	if err != nil {
		return raw
	}
	return out
}
