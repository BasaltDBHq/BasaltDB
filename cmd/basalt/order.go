package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// Display groups of revert lines (CONTRACT.md, CLI, Revert line order):
// rows to restore first (re-inserts, then updates, then deletes), then the
// rows left alone.
const (
	groupReinsert = iota
	groupRestore
	groupDelete
	groupSkip
)

func displayGroup(l revert.Line) int {
	if l.Action == revert.ActionSkip {
		return groupSkip
	}
	switch l.Op {
	case "INSERT":
		return groupReinsert
	case "DELETE":
		return groupDelete
	}
	return groupRestore
}

// displayOrder returns the lines in reading order: by group, table, then
// primary key in natural order; redacted lines last in their table, by
// row hash. Display only: the signed order is never changed.
func displayOrder(lines []revert.Line) []revert.Line {
	out := slices.Clone(lines)
	slices.SortStableFunc(out, func(a, b revert.Line) int {
		if c := displayGroup(a) - displayGroup(b); c != 0 {
			return c
		}
		if c := strings.Compare(a.Table, b.Table); c != 0 {
			return c
		}
		if a.Redacted != b.Redacted {
			if a.Redacted {
				return 1
			}
			return -1
		}
		if a.Redacted {
			return strings.Compare(a.RowHash, b.RowHash)
		}
		return compareKeys(a.Key, b.Key)
	})
	return out
}

// compareKeys compares two primary keys (JSON objects with the same
// columns in the same order) value by value.
func compareKeys(a, b json.RawMessage) int {
	va, errA := keyValues(a)
	vb, errB := keyValues(b)
	if errA != nil || errB != nil {
		return bytes.Compare(a, b)
	}
	for i := range min(len(va), len(vb)) {
		if c := compareValues(va[i], vb[i]); c != 0 {
			return c
		}
	}
	return len(va) - len(vb)
}

// keyValues are the values of a JSON object in their written order.
func keyValues(raw json.RawMessage) ([]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("key is not an object")
	}
	var out []any
	for dec.More() {
		if _, err := dec.Token(); err != nil { // the column name
			return nil, err
		}
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

// compareValues orders numbers by value and strings naturally; anything
// else (or a mix) by its JSON text.
func compareValues(a, b any) int {
	if na, ok := a.(json.Number); ok {
		if nb, ok := b.(json.Number); ok {
			if c, ok := compareNumbers(na, nb); ok {
				return c
			}
		}
	}
	if sa, ok := a.(string); ok {
		if sb, ok := b.(string); ok {
			return naturalCompare(sa, sb)
		}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Compare(ja, jb)
}

func compareNumbers(a, b json.Number) (int, bool) {
	ra, okA := new(big.Rat).SetString(a.String())
	rb, okB := new(big.Rat).SetString(b.String())
	if !okA || !okB {
		return 0, false
	}
	return ra.Cmp(rb), true
}

// naturalCompare compares strings with runs of digits compared by value:
// "lead-2" before "lead-10".
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		da, restA := digitRun(a)
		db, restB := digitRun(b)
		if da != "" && db != "" {
			if c := compareDigits(da, db); c != 0 {
				return c
			}
			a, b = restA, restB
			continue
		}
		if a[0] != b[0] {
			return int(a[0]) - int(b[0])
		}
		a, b = a[1:], b[1:]
	}
	return len(a) - len(b)
}

func digitRun(s string) (digits, rest string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// compareDigits compares two runs of ASCII digits by value, then by
// length, so "01" and "1" have a fixed order.
func compareDigits(a, b string) int {
	ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(ta) != len(tb) {
		return len(ta) - len(tb)
	}
	if c := strings.Compare(ta, tb); c != 0 {
		return c
	}
	return len(a) - len(b)
}
