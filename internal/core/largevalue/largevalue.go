// Package largevalue holds the rules for large values in what the ledger
// tools read for an agent (CONTRACT.md, Large values): the caps, what a
// value costs, the marker's entry and the summaries the person's CLI
// shows. The store leaves out each value over ValueCap and every image that
// would take its item over ItemCap, and returns a marker with the value's
// size and SHA-256 in its place, so a large value never crosses the wire on
// an agent's call; for Postgres that is SQL in
// internal/platform/postgres/pglargevalue. The person's CLI reads the same
// rows without it, in full.
package largevalue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Caps in the budget's unit (resultsize.RowCost): the bytes of a value's
// JSON text as the store prints it, plus EscapeCost per byte JSON escapes,
// plus ValueOverhead, plus its field's name.
const (
	kib = 1 << 10
	mib = 1 << 20
	// ValueCap is the most one value may cost and still be read.
	ValueCap = 1 << 20
	// ItemCap is the most an item's kept images and markers may cost.
	ItemCap = 8 << 20
	// MaxChangeIDs is how many changeIds a revert line carries on an agent
	// read; moreChangeIds counts the rest.
	MaxChangeIDs = 100
	// ValueOverhead and EscapeCost are resultsize's: what a value costs
	// beyond its bytes, and what JSON adds for one byte it escapes.
	ValueOverhead = 128
	EscapeCost    = 6
	// EntryCost is what one largeValues entry costs at most: five short
	// fields and a 64-character hash.
	EntryCost = 1 << 10
)

// Where a value was (large-value.schema.json, in).
const (
	InKey       = "KEY"
	InBefore    = "BEFORE"
	InAfter     = "AFTER"
	InNow       = "NOW"
	InSet       = "SET"
	InStatement = "STATEMENT"
	InParams    = "PARAMS"
)

// Entry is one value, or one whole image, left out (large-value.schema.json).
type Entry struct {
	In     string `json:"in"`
	Column string `json:"column,omitempty"`
	Index  *int   `json:"index,omitempty"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Cost is what the value with this JSON text costs in column, measured as
// the agent's marker measures it (the store computes the same number): the
// text's bytes, EscapeCost for each byte JSON escapes, ValueOverhead and the
// field's name. jsonText is the text as the store prints it, which a
// json.RawMessage of the row's JSON keeps byte for byte.
func Cost(jsonText []byte, column string) int64 {
	var escapes int64
	for _, b := range jsonText {
		switch b {
		case '"', '\\', '<', '>', '&':
			escapes++
		}
	}
	return int64(len(jsonText)) + EscapeCost*escapes + ValueOverhead + int64(len(column))
}

// Text is the value's text as the marker hashes it: a JSON string's
// characters, anything else its JSON text.
func Text(jsonText []byte) (string, error) {
	t := bytes.TrimSpace(jsonText)
	if len(t) > 0 && t[0] == '"' {
		var s string
		if err := json.Unmarshal(t, &s); err != nil {
			return "", fmt.Errorf("largevalue: string value: %w", err)
		}
		return s, nil
	}
	return string(jsonText), nil
}

// SizeText is a size in KiB (under 1 MiB) or MiB, with one decimal, the way
// the signing pages show it.
func SizeText(n int64) string {
	unit, suffix := int64(kib), "KiB"
	if n >= mib {
		unit, suffix = mib, "MiB"
	}
	tenths := (n*10 + unit/2) / unit
	return fmt.Sprintf("%d.%d %s", tenths/10, tenths%10, suffix)
}

// Summary is "(<size>, sha256 <hash>)" for a value that costs over ValueCap
// in column, so the person can match it to a marker an agent saw, and ""
// for any other. The size and hash are over the value's text (Text).
func Summary(jsonText []byte, column string) string {
	if Cost(jsonText, column) <= ValueCap {
		return ""
	}
	text, err := Text(jsonText)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(text))
	return fmt.Sprintf("(%s, sha256 %s)", SizeText(int64(len(text))), hex.EncodeToString(sum[:]))
}

// ImageMarks is Summary for each column of a row image (a JSON object as
// the store prints it): only the columns that cost over ValueCap are in it.
func ImageMarks(image []byte) (map[string]string, error) {
	var cols map[string]json.RawMessage
	if err := json.Unmarshal(image, &cols); err != nil {
		return nil, fmt.Errorf("largevalue: row image: %w", err)
	}
	var out map[string]string
	for col, v := range cols {
		if s := Summary(v, col); s != "" {
			if out == nil {
				out = map[string]string{}
			}
			out[col] = s
		}
	}
	return out, nil
}

// Marks are the summaries of the large values in a row change's key,
// before and after images, by column.
type Marks struct {
	Key, Before, After map[string]string
}
