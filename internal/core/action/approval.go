package action

import (
	"time"

	"github.com/google/uuid"
)

// HoldRequest is a write to store for the person's approval: Basalt's op of
// the write (the store's adapter writes its own verb from it), the request
// as the agent sent it, the fields whose new values the approval binds and
// the preview lines the person signs, both from the store's preview
// (HeldPreview).
type HoldRequest struct {
	Op       Op
	Request  Request
	Assigned []string
	Lines    []string
}

// HeldPreview is a held write's preview, as the store worked it out: the
// fields whose new values the approval binds (Postgres: the columns the
// write assigns, or for an INSERT without a column list every column of its
// table) and the preview lines.
type HeldPreview struct {
	Assigned []string
	Lines    []string
}

// PreviewFailedError marks an error of a held write's preview run, which the
// agent records as a refused write. It reads as the error it wraps.
type PreviewFailedError struct {
	Err error
}

func (e *PreviewFailedError) Error() string { return e.Err.Error() }

func (e *PreviewFailedError) Unwrap() error { return e.Err }

// Held is a stored held write.
type Held struct {
	ApprovalID  uuid.UUID
	BindingText string
	ExpiresAt   time.Time
}
