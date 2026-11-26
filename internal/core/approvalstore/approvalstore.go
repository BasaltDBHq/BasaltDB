package approvalstore

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

// HeldRun is what re-runs a held write for a reveal: the run, task and
// intent it was held in, from the binding's shared part, and the binding's
// request as the person signed it, which only the store reads.
type HeldRun struct {
	Intent  action.Intent
	Request approval.HeldRequest
}

// HoldRequest is a write to store for the person's approval: Basalt's op of
// the write (the store's adapter writes its own verb from it), the request
// as the agent sent it, the fields whose new values the approval binds and
// the preview lines the person signs, both from the store's preview
// (HeldPreview).
type HoldRequest struct {
	Op       action.Op
	Request  action.Request
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

// ApprovalReason is why the store refused an approval call, in the
// approval's own words. The store's adapter maps its own answers to one,
// per call; the service decides on it. Reasons are internal: they never
// reach the wire.
type ApprovalReason string

const (
	// ApprovalNotFound is an approval the calling agent does not hold, or
	// none.
	ApprovalNotFound ApprovalReason = "NOT_FOUND"
	// ApprovalRevealRefused is a reveal proof or key the store did not
	// accept.
	ApprovalRevealRefused ApprovalReason = "REVEAL_REFUSED"
	// ApprovalRevealRowsChanged is a reveal whose re-run preview no longer
	// matches the lines the person signs.
	ApprovalRevealRowsChanged ApprovalReason = "REVEAL_ROWS_CHANGED"
	// ApprovalNotOpen is an approval signed or used meanwhile, for a call
	// that needs it still waiting for the person.
	ApprovalNotOpen ApprovalReason = "NOT_OPEN"
)

// ApprovalRefusalError is an approval call the store refused, as the store's
// adapter maps it. It wraps the adapter's own error, so any other reader
// of that error still finds it.
type ApprovalRefusalError struct {
	Reason ApprovalReason
	// Detail is the store's own text, verbatim.
	Detail string
	// Err is the store's own error, kept in the chain for its other
	// readers.
	Err error
}

// Error is the store's own text, or the reason and detail without one.
func (e *ApprovalRefusalError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Detail == "" {
		return "approval refused: " + string(e.Reason)
	}
	return "approval refused: " + string(e.Reason) + ": " + e.Detail
}

func (e *ApprovalRefusalError) Unwrap() error { return e.Err }

// ApprovalRefusalOf is the approval refusal in err's chain, nil when there
// is none.
func ApprovalRefusalOf(err error) *ApprovalRefusalError {
	var ar *ApprovalRefusalError
	if !errors.As(err, &ar) {
		return nil
	}
	return ar
}

// IsApprovalRefused reports whether err is an approval refusal for reason.
func IsApprovalRefused(err error, reason ApprovalReason) bool {
	ar := ApprovalRefusalOf(err)
	return ar != nil && ar.Reason == reason
}
