package action

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// ChangeListParams lists change records. RunID uuid.Nil means every run.
// The handler applies pagination defaults and the clamp before calling.
type ChangeListParams struct {
	pagination.Params
	RunID uuid.UUID
}

// Change is one change record (CONTRACT.md "The change record").
type Change struct {
	ID     uuid.UUID
	At     time.Time
	Agent  string
	RunID  uuid.NullUUID
	TaskID uuid.NullUUID
	Intent string
	Op     string
	// Verb is the store's own word for the request's operation (CONTRACT.md,
	// Stores, Operations), "" on REVERT and on an OTHER with no command.
	Verb         string
	Table        string
	Statement    string
	Params       json.RawMessage
	Rows         int
	CascadedRows int
	DurationMs   *int
	Status       string
	Code         string
	Reason       string
	// ActorKind is AGENT, or PERSON for a revert (M3).
	ActorKind string
	// RevertID is the revert a REVERT change carried out.
	RevertID uuid.NullUUID
	// RevertedBy lists the revert changes that restored rows of this one.
	RevertedBy []uuid.UUID
	// LargeValues names the statement or params left out of an agent's read
	// (ListChangesMarked; CONTRACT.md, Large values); nil on the person's.
	LargeValues []largevalue.Entry
}

// RowChange is one row a change wrote, cascades included. Key, Before and
// After are nil when Redacted (the agent cannot SELECT the table) or
// Pruned (older than 30 days).
type RowChange struct {
	Seq      int64
	Table    string
	Op       string
	Key      map[string]any
	Before   map[string]any
	After    map[string]any
	Cascaded bool
	Redacted bool
	Pruned   bool
	// BasedOn is the version of the row the run had read (M1.5), nil when
	// the run never read it (BlindWrite) or for an insert or cascaded row.
	BasedOn    *BasedOn
	BlindWrite bool
	// LargeValues names the values left out of an agent's read
	// (RowChangesMarked), and KeyLeftOut, BeforeLeftOut and AfterLeftOut
	// the images left out whole: absent on the wire, never null.
	LargeValues                             []largevalue.Entry
	KeyLeftOut, BeforeLeftOut, AfterLeftOut bool
}

// BasedOn is the row version a write was based on (CONTRACT.md).
type BasedOn struct {
	Version  string    `json:"version"`
	ChangeID uuid.UUID `json:"changeId"`
}

// Approval is one of the calling agent's held writes.
type Approval struct {
	ID          uuid.UUID
	RunID       uuid.UUID
	TaskID      uuid.NullUUID
	Intent      string
	Request     HeldRequest
	Assigned    []string
	Rows        int
	Status      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ApprovedAt  *time.Time
	BindingText string
	Lines       []string
	// LargeValues names the request's text or params left out of an
	// agent's list (CONTRACT.md, Large values): Request.Text is then empty,
	// Request.Params nil.
	LargeValues []largevalue.Entry
	// LinesLeftOut says an agent's read left the lines out because the
	// request is too large for a link (withRequest): Lines are then the
	// lines' heads. LinesCost is the lines' cost in the budget's unit, 0 on
	// a read with no budget.
	LinesLeftOut bool
	LinesCost    int64
}

// HeldRequest is the request a write was held for, as the store holds it:
// its family (the binding's request.kind), its text and its parameters.
type HeldRequest struct {
	Kind   string
	Text   string
	Params json.RawMessage
}

// Revert is a revert the calling role prepared (basalt_meta.agent_reverts).
// Lines are every line of a one-call revert, or a batched plan's sample.
// SignedAt, ApplyBy and the progress counts are set on batched plans.
type Revert struct {
	ID          uuid.UUID
	Status      string
	Scope       string
	ScopeID     uuid.UUID
	Intent      string
	Rows        int
	Skipped     int
	ExpiresAt   time.Time
	BindingText string
	Lines       []string
	Batched     bool
	SignedAt    *time.Time
	ApplyBy     *time.Time
	Batches     int
	Progress    RevertProgress
	// ChangeID is the revert's own change record (op REVERT), set once a
	// one-call revert is applied or a batched plan is signed.
	ChangeID *uuid.UUID
	// Widened is set once the person widened the revert beyond the role's
	// own work (version 20): the view then shows no binding, selection or
	// lines.
	Widened bool
	// RejectedAt and RejectNote are set on a REJECTED revert: when the
	// person rejected it, and the note they wrote for the agent ("" for
	// none).
	RejectedAt *time.Time
	RejectNote string
	// CreatedAt is when the revert was prepared.
	CreatedAt time.Time
	// LinesLeftOut and LinesCost are as on Approval: an agent's read left
	// the lines out (Lines are their heads), and what they cost.
	LinesLeftOut bool
	LinesCost    int64
}

// RevertProgress counts a batched plan's lines by outcome.
type RevertProgress struct {
	Restored int
	Skipped  int
	Pending  int
}

// RevertListParams lists the calling role's open reverts. Status "" means
// PENDING and APPLYING.
type RevertListParams struct {
	pagination.Params
	Status string
}

// RunListParams lists the calling agent's own runs (list_runs). StartTime
// (inclusive) and EndTime (exclusive) filter on the run's start; nil means
// no bound. The handler applies pagination defaults and the clamp before
// calling.
type RunListParams struct {
	pagination.Params
	StartTime *time.Time `json:"startTime"`
	// EndTime must be after StartTime when both are given: excluded_with
	// passes when there is no StartTime, gtfield checks the order otherwise.
	EndTime *time.Time `json:"endTime" validate:"excluded_with=StartTime|gtfield=StartTime"`
}
