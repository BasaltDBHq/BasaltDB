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
	Field  string `json:"field,omitempty"`
	Index  *int   `json:"index,omitempty"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
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
