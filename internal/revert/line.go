package revert

import (
	"bytes"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
)

// What a revert does with a row.
const (
	ActionRestore = "RESTORE"
	ActionSkip    = "SKIP"
)

// Conflict reasons: why a row is skipped (CONTRACT.md, Revert, Conflicts).
const (
	ConflictChangedAfter    = "CHANGED_AFTER"
	ConflictRowGone         = "ROW_GONE"
	ConflictKeyTaken        = "KEY_TAKEN"
	ConflictAlreadyReverted = "ALREADY_REVERTED"
	ConflictValuesPruned    = "VALUES_PRUNED"
	ConflictSchemaChanged   = "SCHEMA_CHANGED"
	ConflictCascade         = "CASCADE"
	ConflictConstraint      = "CONSTRAINT"
)

var conflicts = map[string]bool{
	ConflictChangedAfter: true, ConflictRowGone: true, ConflictKeyTaken: true, ConflictAlreadyReverted: true,
	ConflictValuesPruned: true, ConflictSchemaChanged: true, ConflictCascade: true, ConflictConstraint: true,
}

// Line is one parsed revert line. Key, Now and Set keep the person's column
// names and values exactly as Postgres returned them. Op is the inverse
// write the revert runs. A redacted line has no Key, Now, Set or SQLState.
type Line struct {
	Op        string          `json:"op"`
	Key       json.RawMessage `json:"key,omitempty"`
	Now       json.RawMessage `json:"now,omitempty"`
	Set       json.RawMessage `json:"set,omitempty"`
	Table     string          `json:"table"`
	Action    string          `json:"action"`
	Cascaded  bool            `json:"cascaded"`
	Conflict  *string         `json:"conflict"`
	SQLState  *string         `json:"sqlState,omitempty"`
	ChangeIDs []uuid.UUID     `json:"changeIds"`
	Redacted  bool            `json:"redacted,omitempty"`
	RowHash   string          `json:"rowHash,omitempty"`
}

// ParseLine parses one revert line for display and checks its action and
// conflict agree: a RESTORE line has no conflict, a SKIP line names one.
func ParseLine(text string) (Line, error) {
	var l Line
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Line{}, invalid("revert line: %v", err)
	}
	switch l.Op {
	case approval.OpInsert, approval.OpUpdate, approval.OpDelete:
	default:
		return Line{}, invalid("revert line op %q", l.Op)
	}
	if l.Table == "" {
		return Line{}, invalid("revert line without a table")
	}
	if len(l.ChangeIDs) == 0 {
		return Line{}, invalid("revert line names no change")
	}
	switch l.Action {
	case ActionRestore:
		if l.Conflict != nil {
			return Line{}, invalid("RESTORE line with conflict %q", *l.Conflict)
		}
	case ActionSkip:
		if l.Conflict == nil || !conflicts[*l.Conflict] {
			return Line{}, invalid("SKIP line without a known conflict")
		}
	default:
		return Line{}, invalid("revert line action %q", l.Action)
	}
	return l, nil
}
