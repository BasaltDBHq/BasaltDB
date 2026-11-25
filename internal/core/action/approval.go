package action

import (
	"time"

	"github.com/google/uuid"
)

// HoldRequest is a write the guard held, to store for the person's
// approval: the statement's own command (the store's verb), the statement
// and parameters as given, the columns whose new values the approval
// binds, and the preview lines the person signs.
type HoldRequest struct {
	Verb      string
	Statement string
	Params    []any
	Assigned  []string
	Lines     []string
}

// Held is a stored held write.
type Held struct {
	ApprovalID  uuid.UUID
	BindingText string
	ExpiresAt   time.Time
}
