// Package textrule checks that a text a person signs follows the text rules
// (CONTRACT.md, Stores, Text rules): the exact layout every store writes for
// a binding and its lines, so a passkey signature and rowsHash cover the
// same bytes whoever reads them. It never re-serializes a text: it reads the
// bytes as they are and refuses any that another writer could have laid out
// differently.
package textrule

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// ErrBroken wraps every reason a text breaks the rules.
var ErrBroken = errors.New("text does not follow the text rules")

// maxDepth caps how deep objects and arrays nest, so a crafted text cannot
// exhaust the stack.
const maxDepth = 64

// shortEscapeLen is the length of a two-character escape such as `\n`.
const shortEscapeLen = 2

// Check reports whether text is one JSON object laid out by the text rules:
// keys unique and sorted by their UTF-8 bytes (shorter first, then
// bytewise) at every depth, entries and values joined by ", ", an entry
// written `"key": value`, strings escaped only as the rules say, literals
// lowercase, numbers valid JSON, and nothing after the object.
func Check(text string) error {
	if !utf8.ValidString(text) {
		return broken(0, "is not UTF-8")
	}
	s := scanner{text: text}
	if s.peek() != '{' {
		return broken(0, "is not an object")
	}
	if err := s.value(0); err != nil {
		return err
	}
	if s.pos != len(text) {
		return broken(s.pos, "has data after its end")
	}
	return nil
}

// Timestamp is the form of a timestamp Basalt writes: UTC, six fraction
// digits and Z.
var Timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

// PlainInteger reports whether raw is one of Basalt's own integers: decimal
// digits with no sign, no leading zero, no fraction and no exponent.
func PlainInteger(raw []byte) bool {
	if len(raw) == 0 || (raw[0] == '0' && len(raw) > 1) {
		return false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func broken(pos int, format string, args ...any) error {
	return fmt.Errorf("%w: at byte %d: %s", ErrBroken, pos, fmt.Sprintf(format, args...))
}

type scanner struct {
	text string
	pos  int
}

func (s *scanner) peek() byte {
	if s.pos >= len(s.text) {
		return 0
	}
	return s.text[s.pos]
}

func (s *scanner) expect(lit string) error {
	if len(s.text)-s.pos < len(lit) || s.text[s.pos:s.pos+len(lit)] != lit {
		return broken(s.pos, "expects %q", lit)
	}
	s.pos += len(lit)
	return nil
}

func (s *scanner) value(depth int) error {
	if depth > maxDepth {
		return broken(s.pos, "nests deeper than %d", maxDepth)
	}
	switch c := s.peek(); {
	case c == '{':
		return s.object(depth)
	case c == '[':
		return s.array(depth)
	case c == '"':
		_, err := s.str()
		return err
	case c == 't':
		return s.expect("true")
	case c == 'f':
		return s.expect("false")
	case c == 'n':
		return s.expect("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	default:
		return broken(s.pos, "expects a value")
	}
}

func (s *scanner) object(depth int) error {
	s.pos++ // {
	if s.peek() == '}' {
		s.pos++
		return nil
	}
	var prev []byte
	for i := 0; ; i++ {
		at := s.pos
		key, err := s.str()
		if err != nil {
			return err
		}
		if i > 0 && !keyBefore(prev, key) {
			return broken(at, "key %q is out of order or repeated", key)
		}
		prev = key
		if err := s.expect(": "); err != nil {
			return err
		}
		if err := s.value(depth + 1); err != nil {
			return err
		}
		if s.peek() == '}' {
			s.pos++
			return nil
		}
		if err := s.expect(", "); err != nil {
			return err
		}
	}
}

// keyBefore reports whether a sorts strictly before b: shorter first, then
// bytewise, as Postgres's jsonb orders keys.
func keyBefore(a, b []byte) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return bytes.Compare(a, b) < 0
}

func (s *scanner) array(depth int) error {
	s.pos++ // [
	if s.peek() == ']' {
		s.pos++
		return nil
	}
	for {
		if err := s.value(depth + 1); err != nil {
			return err
		}
		if s.peek() == ']' {
			s.pos++
			return nil
		}
		if err := s.expect(", "); err != nil {
			return err
		}
	}
}

// shortEscapes are the two-character escapes the rules allow, by the
// character they stand for.
var shortEscapes = map[byte]byte{'"': '"', '\\': '\\', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

// str reads a string and returns its decoded bytes. Only `\"`, `\\`, `\b`,
// `\f`, `\n`, `\r`, `\t` and, for any other character below U+0020,
// `\u00xx` in lowercase hex are escapes; every other character is written
// as it is.
func (s *scanner) str() ([]byte, error) {
	if s.peek() != '"' {
		return nil, broken(s.pos, "expects a string")
	}
	s.pos++
	var out []byte
	for {
		if s.pos >= len(s.text) {
			return nil, broken(s.pos, "has an unterminated string")
		}
		c := s.text[s.pos]
		switch {
		case c == '"':
			s.pos++
			return out, nil
		case c < 0x20:
			return nil, broken(s.pos, "has a control character written as it is")
		case c != '\\':
			out = append(out, c)
			s.pos++
			continue
		}
		decoded, err := s.escape()
		if err != nil {
			return nil, err
		}
		out = append(out, decoded)
	}
}

// uEscapeLen is the length of `\u00xx`.
const uEscapeLen = 6

func (s *scanner) escape() (byte, error) {
	at := s.pos
	if s.pos+1 >= len(s.text) {
		return 0, broken(at, "has an unterminated escape")
	}
	e := s.text[s.pos+1]
	if d, ok := shortEscapes[e]; ok {
		s.pos += shortEscapeLen
		return d, nil
	}
	if e != 'u' || len(s.text)-s.pos < uEscapeLen || s.text[s.pos+2:s.pos+4] != "00" {
		return 0, broken(at, "has an escape the rules do not write")
	}
	hi, lo := hexDigit(s.text[s.pos+4]), hexDigit(s.text[s.pos+5])
	if hi < 0 || lo < 0 {
		return 0, broken(at, "has a \\u escape that is not lowercase hex")
	}
	c := byte(hi<<4 | lo)
	if c >= 0x20 {
		return 0, broken(at, "escapes a character the rules write as it is")
	}
	if _, short := shortFor[c]; short {
		return 0, broken(at, "writes a \\u escape for a character with a short escape")
	}
	s.pos += uEscapeLen
	return c, nil
}

// shortFor are the control characters that have a two-character escape.
var shortFor = map[byte]bool{'\b': true, '\f': true, '\n': true, '\r': true, '\t': true}

func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10 //nolint:mnd // a hex digit's value
	default:
		return -1
	}
}

// number reads a JSON number: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?.
func (s *scanner) number() error {
	at := s.pos
	if s.peek() == '-' {
		s.pos++
	}
	switch c := s.peek(); {
	case c == '0':
		s.pos++
	case c >= '1' && c <= '9':
		s.digits()
	default:
		return broken(at, "has a number with no digits")
	}
	if s.peek() == '.' {
		s.pos++
		if s.digits() == 0 {
			return broken(at, "has a number with no digits after its point")
		}
	}
	if c := s.peek(); c == 'e' || c == 'E' {
		s.pos++
		if c := s.peek(); c == '+' || c == '-' {
			s.pos++
		}
		if s.digits() == 0 {
			return broken(at, "has a number with no digits in its exponent")
		}
	}
	return nil
}

func (s *scanner) digits() int {
	n := 0
	for c := s.peek(); c >= '0' && c <= '9'; c = s.peek() {
		s.pos++
		n++
	}
	return n
}
