// Package textruletest writes JSON in the text rules' layout for tests
// that build a binding or a line from a struct: in production only the
// store writes these texts, and nothing re-serializes them.
package textruletest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TimeLayout is the timestamp form Basalt writes (CONTRACT.md, Stores,
// Text rules): UTC, six fraction digits and Z.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// Text returns v's JSON laid out by the text rules. A key named expiresAt
// whose value is a timestamp is written in TimeLayout, as the store
// writes it.
func Text(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return Canonical(raw)
}

// MustText is Text for test fixtures: it panics on a value that does not
// marshal.
func MustText(v any) string {
	text, err := Text(v)
	if err != nil {
		panic(err)
	}
	return text
}

// Canonical re-lays raw JSON by the text rules.
func Canonical(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	var b strings.Builder
	write(&b, "", v)
	return b.String(), nil
}

func write(b *strings.Builder, key string, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		fmt.Fprintf(b, "%t", x)
	case json.Number:
		b.WriteString(x.String())
	case string:
		if key == "expiresAt" {
			if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
				x = t.UTC().Format(TimeLayout)
			}
		}
		quote(b, x)
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			write(b, "", item)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			quote(b, k)
			b.WriteString(": ")
			write(b, k, x[k])
		}
		b.WriteByte('}')
	}
}

var short = map[rune]string{'"': `\"`, '\\': `\\`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`}

func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		if e, ok := short[r]; ok {
			b.WriteString(e)
			continue
		}
		if r < 0x20 {
			fmt.Fprintf(b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
}
