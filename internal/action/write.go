package action

import (
	"time"

	"github.com/google/uuid"
)

// WriteResult is one applied write.
type WriteResult struct {
	ChangeID uuid.UUID
	// Rows is what the guard counted for the action, cascades included.
	Rows      int
	Duration  time.Duration
	Columns   []Column
	Returning []map[string]any
}

// Refusal is an action the policy, the guard or the database refused, to
// record.
type Refusal struct {
	Intent Intent
	// Op is OpSelect, OpInsert, OpUpdate, OpDelete or OpOther.
	Op        Op
	Statement string
	Params    []any
	Code      string
	Reason    string
	Duration  time.Duration
}
