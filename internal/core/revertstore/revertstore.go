package revertstore

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// The revert types name the signed-message codecs (revert, passkey,
// approval): what the person signs is the same whatever the store, so they
// are part of the vocabulary, not of an adapter.

// ErrEmptyProposal is a task revert with no line of the agent's own.
var ErrEmptyProposal = errors.New("the task has no line of this agent's own to revert")

// RevertReason is why the store refused a revert call, in the revert's own
// words. The store's adapter maps its own answers to one, per call; the
// service decides on it. Reasons are internal: they never reach the wire.
type RevertReason string

const (
	// RevertNotFound is a revert the calling agent did not prepare, or none.
	RevertNotFound RevertReason = "NOT_FOUND"
	// RevertExpiredReason is a revert past its deadline (RevertExpired is
	// the status the ledger keeps).
	RevertExpiredReason RevertReason = "EXPIRED"
	// RevertNothing is a scope, or a signed revert, with no row to restore.
	RevertNothing RevertReason = "NOTHING_TO_REVERT"
	// RevertReadsOnly is a scope that changed no row a revert could restore.
	RevertReadsOnly RevertReason = "READS_ONLY"
	// RevertRowsChanged is a signed revert whose rows changed since the
	// preview: nothing was reverted.
	RevertRowsChanged RevertReason = "ROWS_CHANGED"
	// RevertPasskeyRevoked is a signature by a passkey no longer registered.
	RevertPasskeyRevoked RevertReason = "PASSKEY_REVOKED"
	// RevertAlreadySigned is a signature on a revert already signed or
	// applied.
	RevertAlreadySigned RevertReason = "ALREADY_SIGNED"
	// RevertWithdrawnReason is a signature on a revert the agent withdrew
	// (RevertWithdrawn is the status the ledger keeps).
	RevertWithdrawnReason RevertReason = "WITHDRAWN"
	// RevertSignature is any other signature the store did not accept.
	RevertSignature RevertReason = "SIGNATURE_REFUSED"
	// RevertNotPending is a revert signed, applied or rejected meanwhile,
	// for a call that needs it still waiting for the person.
	RevertNotPending RevertReason = "NOT_PENDING"
	// RevertWidenRefused is a failed proof or scope token check of a
	// rescope or of a reject after a widen.
	RevertWidenRefused RevertReason = "WIDEN_REFUSED"
	// RevertRevealRefused is a failed reveal proof.
	RevertRevealRefused RevertReason = "REVEAL_REFUSED"
	// RevertNotOwnChange, RevertNotOwnRun and RevertNotOwnTask are a scope
	// that is not the agent's own change, run or task.
	RevertNotOwnChange RevertReason = "NOT_OWN_CHANGE"
	RevertNotOwnRun    RevertReason = "NOT_OWN_RUN"
	RevertNotOwnTask   RevertReason = "NOT_OWN_TASK"
	// RevertFilter is a filter naming work that is not the agent's.
	RevertFilter RevertReason = "FILTER"
	// RevertFilterName is a filter holding a resource name the store
	// cannot use, whoever's work it would name. Detail is the store's text.
	RevertFilterName RevertReason = "FILTER_NAME"
	// RevertFilterCap is a filter over its length limit.
	RevertFilterCap RevertReason = "FILTER_CAP"
	// RevertTimedOut is a call the store stopped at its time limit.
	RevertTimedOut RevertReason = "TIMED_OUT"
	// RevertInvalid is any other scope the store refused.
	RevertInvalid RevertReason = "INVALID"
)

// RevertRefusalError is a revert call the store refused, as the store's adapter
// maps it. It wraps the adapter's own error, so any other reader of that
// error still finds it.
type RevertRefusalError struct {
	Reason RevertReason
	// Detail is the store's own text, shown verbatim where the answer
	// shows what the store said.
	Detail string
	// StoreCode is the store's own error code, when it has one.
	StoreCode string
	// Err is the store's own error, kept in the chain for its other
	// readers.
	Err error
}

// Error is the store's own text, or the reason and detail without one.
func (e *RevertRefusalError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Detail == "" {
		return "revert refused: " + string(e.Reason)
	}
	return "revert refused: " + string(e.Reason) + ": " + e.Detail
}

func (e *RevertRefusalError) Unwrap() error { return e.Err }

// RevertRefusalOf is the revert refusal in err's chain, nil when there is
// none.
func RevertRefusalOf(err error) *RevertRefusalError {
	var rr *RevertRefusalError
	if !errors.As(err, &rr) {
		return nil
	}
	return rr
}

// Scope is what a revert covers: one change, run or task of the caller,
// narrowed to some of its runs (a task only) and resources.
type Scope struct {
	Kind revert.Scope
	ID   uuid.UUID
	// Runs narrows a TASK to some of the caller's runs in it; nil for all.
	Runs []uuid.UUID
	// Resources narrows the lines to some resource names, in the store's
	// form (Postgres: schema.table); nil for all.
	Resources []string
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

// BatchItem is one line of an applied batch. StoreCode is the store's own
// error code for a skipped line, when it has one.
type BatchItem struct {
	Line      int    `json:"line"`
	Outcome   string `json:"outcome"`
	Conflict  string `json:"conflict,omitempty"`
	StoreCode string `json:"storeCode,omitempty"`
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

// CatalogTable is one resource in a catalog: its name in the store's form
// and the rows written there.
type CatalogTable struct {
	Table string `json:"resource"`
	Rows  int    `json:"rows"`
}

// RevertCatalog lists the agents, runs and tables inside the select the
// person proved, and the agent role of each change in it (nil when the
// store does not say).
type RevertCatalog struct {
	Agents       []CatalogAgent       `json:"agents"`
	Runs         []CatalogRun         `json:"runs"`
	Tables       []CatalogTable       `json:"resources"`
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

// RevertLine is one line of a batched plan: its number (execution order),
// the signed text, and what happened to it. StoreCode is the store's own
// error code for a skipped line, when it has one. Batch is nil while
// pending.
type RevertLine struct {
	No        int
	Text      string
	Outcome   string
	Conflict  string
	StoreCode string
	Batch     *int
}

// RevertLineParams lists a batched plan's lines in number order. Outcome
// "" lists every line.
type RevertLineParams struct {
	pagination.Params
	RevertID uuid.UUID
	Outcome  string
}
