package guardmodel

import "github.com/basaltdbhq/basaltdb/internal/core/approval"

// RevealRefused is the one detail of APPROVAL_INVALID and REVERT_INVALID for
// every failed reveal proof, key, nonce or ticket check (CONTRACT.md, Rows
// hidden from the agent; version 29).
const RevealRefused = "REVEAL_REFUSED"

// RevealedRevert is reveal_revert_rows' answer: the values of the
// request's redacted lines, or RowsChanged (and no row) when a hidden row
// changed since the revert was prepared. Either way the proof used up the
// revert's reveal nonce.
type RevealedRevert struct {
	Rows        []approval.RevealedRow `json:"rows"`
	RowsChanged bool                   `json:"rowsChanged"`
}

// RevealRowsChanged is the detail of APPROVAL_INVALID when a re-run preview's
// lines no longer match the held approval's (reveal_approval_rows): the
// approval can no longer apply.
const RevealRowsChanged = "ROWS_CHANGED"
