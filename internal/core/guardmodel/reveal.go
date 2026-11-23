package guardmodel

// RevealRefused is the one detail of APPROVAL_INVALID and REVERT_INVALID for
// every failed reveal proof, key, nonce or ticket check (CONTRACT.md, Rows
// hidden from the agent; version 29).
const RevealRefused = "REVEAL_REFUSED"

// RevealRowsChanged is the detail of APPROVAL_INVALID when a re-run preview's
// lines no longer match the held approval's (reveal_approval_rows): the
// approval can no longer apply.
const RevealRowsChanged = "ROWS_CHANGED"
