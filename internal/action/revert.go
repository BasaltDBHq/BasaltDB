package action

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// The revert types name the signed-message codecs (revert, passkey,
// approval): what the person signs is the same whatever the store, so they
// are part of the vocabulary, not of an adapter.

// ErrEmptyProposal is a task revert with no line of the agent's own.
var ErrEmptyProposal = errors.New("the task has no line of this agent's own to revert")

// Scope is what a revert covers: one change, run or task of the caller,
// narrowed to some of its runs (a task only) and tables.
type Scope struct {
	Kind revert.Scope
	ID   uuid.UUID
	// Runs narrows a TASK to some of the caller's runs in it; nil for all.
	Runs []uuid.UUID
	// Tables narrows the lines to some schema.table names; nil for all.
	Tables []string
}

// PreviewLine is one line of a revert preview with the hash of its full
// signed text.
type PreviewLine struct {
	Text string
	Hash string
}

// PreviewPage is one page of a revert preview with the preview's totals.
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
	// Page are the lines after the cursor, at most the limit; More says
	// another page follows.
	Page []PreviewLine
	More bool
}

// PreparedRevert is a revert stored for the person to sign.
type PreparedRevert struct {
	RevertID    uuid.UUID
	BindingText string
	ExpiresAt   time.Time
	Lines       []string
	Batched     bool
	// LineCount is how many lines the revert has. On an agent's call Lines
	// is nil: the agent reads them measured, with the revert.
	LineCount int
}

// BatchItem is one line of an applied batch.
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

// AppliedRevert is an applied revert, or a signed large plan waiting for
// its batches.
type AppliedRevert struct {
	ChangeID uuid.UUID  `json:"changeId"`
	Rows     int        `json:"rows"`
	Skipped  int        `json:"skipped"`
	Batched  bool       `json:"batched,omitempty"`
	Pending  int        `json:"pending,omitempty"`
	ApplyBy  *time.Time `json:"applyBy,omitempty"`
}

// RescopeRequest is one change of a pending revert's scope. A widen sets
// Proof and RescopeKey; a narrow after a widen sets Token.
type RescopeRequest struct {
	RevertID   uuid.UUID
	Select     revert.Select
	Proof      *passkey.Assertion
	RescopeKey []byte
	Token      []byte
}

// CatalogAgent, CatalogRun and CatalogTable are what the person may pick
// from after a widen.
type CatalogAgent struct {
	Agent   string `json:"agent"`
	Changes int    `json:"changes"`
}

type CatalogRun struct {
	RunID     uuid.UUID `json:"runId"`
	Agent     string    `json:"agent"`
	StartedAt time.Time `json:"startedAt"`
	Changes   int       `json:"changes"`
}

type CatalogTable struct {
	Table string `json:"table"`
	Rows  int    `json:"rows"`
}

// RevertCatalog lists the agents, runs and tables inside the select the
// person proved, and the agent role of each change in it (nil when the
// store does not say).
type RevertCatalog struct {
	Agents       []CatalogAgent       `json:"agents"`
	Runs         []CatalogRun         `json:"runs"`
	Tables       []CatalogTable       `json:"tables"`
	ChangeAgents map[uuid.UUID]string `json:"changeAgents,omitempty"`
}

// RescopedRevert is a revert after a rescope or reset: the new binding and
// lines, the nonce the next widen proof signs, and for a proven or
// token-bearing call the catalog; ScopeToken is set only by a proven widen.
type RescopedRevert struct {
	RevertID     uuid.UUID      `json:"revertId"`
	BindingText  string         `json:"binding"`
	ExpiresAt    time.Time      `json:"expiresAt"`
	Lines        []string       `json:"lines"`
	RescopeNonce passkey.Bytes  `json:"rescopeNonce"`
	Catalog      *RevertCatalog `json:"catalog,omitempty"`
	ScopeToken   passkey.Bytes  `json:"scopeToken,omitempty"`
}

// RejectedRevert is a pending revert the person rejected.
type RejectedRevert struct {
	RevertID   uuid.UUID `json:"revertId"`
	Status     string    `json:"status"`
	RejectedAt time.Time `json:"rejectedAt"`
}

// RevealedRevert is the values of a revert's redacted lines, for the
// person's reveal proof.
type RevealedRevert struct {
	Rows        []approval.RevealedRow `json:"rows"`
	RowsChanged bool                   `json:"rowsChanged"`
}
