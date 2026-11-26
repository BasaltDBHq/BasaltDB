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
	// Op is OpRead, OpInsert, OpUpdate, OpDelete or OpOther.
	Op        Op
	Statement string
	Params    []any
	Code      string
	Reason    string
	Duration  time.Duration
	// Resources are the resources the statement names, as the store's check
	// gave them (Statement.Tables); none when it did not parse. The store
	// records them in its own qualified form.
	Resources []string
}
