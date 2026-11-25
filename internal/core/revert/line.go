package revert

import (
	"bytes"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
	"github.com/basaltdbhq/basaltdb/internal/lib/wiretime"
)

// What a revert does with a row.
const (
	ActionRestore = "RESTORE"
	ActionSkip    = "SKIP"
)

// Conflict reasons: why a row is skipped (CONTRACT.md, Revert, Conflicts).
const (
	ConflictChangedAfter    = "CHANGED_AFTER"
	ConflictTargetGone      = "TARGET_GONE"
	ConflictKeyTaken        = "KEY_TAKEN"
	ConflictAlreadyReverted = "ALREADY_REVERTED"
	ConflictValuesPruned    = "VALUES_PRUNED"
	ConflictSchemaChanged   = "SCHEMA_CHANGED"
	ConflictCascade         = "CASCADE"
	ConflictConstraint      = "CONSTRAINT"
)

var conflicts = map[string]bool{
	ConflictChangedAfter: true, ConflictTargetGone: true, ConflictKeyTaken: true, ConflictAlreadyReverted: true,
	ConflictValuesPruned: true, ConflictSchemaChanged: true, ConflictCascade: true, ConflictConstraint: true,
}

// LineStore is a revert line's store part: the store's kind, its own word
// for the inverse write, and its own error code for a line it could not
// restore (null otherwise).
type LineStore struct {
	Kind string  `json:"kind"`
	Verb string  `json:"verb"`
	Code *string `json:"code"`
}

// Line is one parsed revert line. Key, Now and Set keep the person's field
// names and values exactly as the store returned them. Op is the inverse
// write the revert runs. A redacted line has no Key, Now or Set.
type Line struct {
	Op        string          `json:"op"`
	Key       json.RawMessage `json:"key,omitempty"`
	Now       json.RawMessage `json:"now,omitempty"`
	Set       json.RawMessage `json:"set,omitempty"`
	Shape     string          `json:"shape"`
	Store     LineStore       `json:"store"`
	Resource  string          `json:"resource"`
	Action    string          `json:"action"`
	Cascaded  bool            `json:"cascaded"`
	Conflict  *string         `json:"conflict"`
	ChangeIDs []uuid.UUID     `json:"changeIds"`
	Redacted  bool            `json:"redacted,omitempty"`
	RowHash   string          `json:"rowHash,omitempty"`
	// LargeValues and MoreChangeIDs are on a line an agent reads only
	// (ParseMarkedLine; CONTRACT.md, Large values): the values left out of
	// key, now and set, and how many changeIds follow the first
	// largevalue.MaxChangeIDs. A signed line never has them.
	LargeValues   []largevalue.Entry `json:"largeValues,omitempty"`
	MoreChangeIDs int                `json:"moreChangeIds,omitempty"`
	// Marks summarize the large values of key, now (Before) and set
	// (After) for the CLI's text output; set by ForDisplay, never on the wire.
	Marks largevalue.Marks `json:"-"`
}

// imageMarks is largevalue.ImageMarks, none for an image that is not an object.
func imageMarks(image json.RawMessage) map[string]string {
	marks, err := largevalue.ImageMarks(image)
	if err != nil {
		return nil
	}
	return marks
}

// ParseLine parses one signed revert line for display: the text rules,
// then its keys, and its action and conflict agree: a RESTORE line has no
// conflict, a SKIP line names one.
func ParseLine(text string) (Line, error) {
	if err := textrule.Check(text); err != nil {
		return Line{}, Invalid("revert line: %v", err)
	}
	l, err := ParseMarkedLine(text)
	if err != nil {
		return Line{}, err
	}
	if l.LargeValues != nil || l.MoreChangeIDs != 0 {
		return Line{}, Invalid("revert line with largeValues or moreChangeIds: not a signed line")
	}
	return l, nil
}

// ParseMarkedLine is ParseLine for a line as an agent reads it, with large
// values left out and named (ledger.ListRevertLinesMarked,
// guard.PreviewRevertPage).
func ParseMarkedLine(text string) (Line, error) {
	var l Line
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Line{}, Invalid("revert line: %v", err)
	}
	switch l.Op {
	case approval.OpInsert, approval.OpUpdate, approval.OpDelete:
	default:
		return Line{}, Invalid("revert line op %q", l.Op)
	}
	if err := approval.CheckLinePart(l.Shape, l.Store.Kind, l.Store.Verb, l.Resource); err != nil {
		return Line{}, Invalid("revert line %v", err)
	}
	if len(l.ChangeIDs) == 0 {
		return Line{}, Invalid("revert line names no change")
	}
	switch l.Action {
	case ActionRestore:
		if l.Conflict != nil {
			return Line{}, Invalid("RESTORE line with conflict %q", *l.Conflict)
		}
	case ActionSkip:
		if l.Conflict == nil || !conflicts[*l.Conflict] {
			return Line{}, Invalid("SKIP line without a known conflict")
		}
	default:
		return Line{}, Invalid("revert line action %q", l.Action)
	}
	return l, nil
}

// ForDisplay returns the line with its row values as the wire format has
// them (RFC 3339 UTC for a timestamptz). The signed text, which the passkey
// signature and the hashes cover, is never changed: only what is shown.
//
// Marks are measured on the text as signed, before the values are shown
// another way: they must match the agent's marker.
func (l Line) ForDisplay() Line {
	l.Marks = largevalue.Marks{Key: imageMarks(l.Key), Before: imageMarks(l.Now), After: imageMarks(l.Set)}
	l.Key = wiretime.JSON(l.Key)
	l.Now = wiretime.JSON(l.Now)
	l.Set = wiretime.JSON(l.Set)
	return l
}
