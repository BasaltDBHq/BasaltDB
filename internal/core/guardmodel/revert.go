package guardmodel

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// RevertScope is an agent's own proposal of what a revert covers: one of
// its changes, one of its runs, or its own changes in a task it ran in,
// optionally narrowed to some of its runs in that task and some tables
// (CONTRACT.md, Revert, The scope descriptor). The guard builds the
// descriptor with agents = [the calling role] and refuses anything outside
// the caller's own work (BS011 SCOPE_REFUSED).
type RevertScope struct {
	Kind revert.Scope
	ID   uuid.UUID
	// Runs narrows a TASK to some of the caller's runs in it; nil for all.
	Runs []uuid.UUID
	// Tables narrows the lines to some schema.table names; nil for all.
	Tables []string
}

// PreviewPage is one page of a preview as an agent reads it (preview_revert):
// the totals of the whole preview and the page's lines, with values too
// large for the agent left out (CONTRACT.md, Large values).
type PreviewPage struct {
	// Lines and Restore count every line of the preview, and
	// AllAlreadyReverted says whether every one is a SKIP of a row a revert
	// of the scope already restored.
	Lines              int
	Restore            int
	AllAlreadyReverted bool
	// CursorFound is false when a cursor was given and no line of the
	// preview has its hash: the rows changed between pages.
	CursorFound bool
	// Page are the lines after the cursor, at most the limit, each with the
	// hash of its full signed text (the next cursor); More says another
	// page follows.
	Page []PreviewLine
	More bool
}

// PreviewLine is one line of a PreviewPage: its text with large values
// left out, and the SHA-256 (lowercase hex) of the full text.
type PreviewLine struct {
	Text string
	Hash string
}

// PreparedRevert is a revert stored for the person to sign. Lines are every
// line of a one-call revert, or the sample of a batched plan (Batched).
type PreparedRevert struct {
	RevertID    uuid.UUID
	BindingText string
	ExpiresAt   time.Time
	Lines       []string
	Batched     bool
	// LineCount is how many lines the revert has. On an agent's call (a
	// context with a result budget) Lines is nil: the agent reads them
	// measured, with the revert (ledger.FindRevert), so a large revert's
	// lines never cross the wire on its call (CONTRACT.md, Large values).
	LineCount int
}

// Prepare time limits (agent-assisted revert design, Preparing). The
// person's CLI may take minutes on a large scope; an MCP call stays under
// the 2 minutes after which Claude Code moves a tool call to the
// background.
const (
	CLIPrepareTimeout = 10 * time.Minute
	MCPPrepareTimeout = 100 * time.Second
)

// ErrPrepareTimeout is a timeout shorter than the millisecond
// statement_timeout counts in, where 0 would mean no limit at all.
var ErrPrepareTimeout = errors.New("guard: a prepare timeout must be at least 1 ms")

// AppliedRevert is the result of apply_revert: for a one-call revert its
// change record, the rows it restored and the rows it skipped; for a
// batched plan the signature only (Rows 0), the lines still to apply and
// the time they must be applied by.
type AppliedRevert struct {
	ChangeID uuid.UUID  `json:"changeId"`
	Rows     int        `json:"rows"`
	Skipped  int        `json:"skipped"`
	Batched  bool       `json:"batched,omitempty"`
	Pending  int        `json:"pending,omitempty"`
	ApplyBy  *time.Time `json:"applyBy,omitempty"`
}

// Outcomes of a batched plan's lines (CONTRACT.md, Revert, Large plans).
const (
	OutcomePending  = "PENDING"
	OutcomeRestored = "RESTORED"
	OutcomeSkipped  = "SKIPPED"
)

// BatchItem is what one batch did with one line of the plan.
type BatchItem struct {
	Line     int    `json:"line"`
	Outcome  string `json:"outcome"`
	Conflict string `json:"conflict,omitempty"`
	SQLState string `json:"sqlState,omitempty"`
}

// BatchResult is one applied batch: its number, the plan's status and
// totals after it, and this batch's lines in the order given.
type BatchResult struct {
	RevertID uuid.UUID   `json:"revertId"`
	Batch    int         `json:"batch"`
	Status   string      `json:"status"`
	Restored int         `json:"restored"`
	Skipped  int         `json:"skipped"`
	Pending  int         `json:"pending"`
	Items    []BatchItem `json:"items"`
}
