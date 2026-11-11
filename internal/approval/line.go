package approval

import (
	"bytes"
	"encoding/json"
)

// Row operations in a preview line.
const (
	OpInsert = "INSERT"
	OpUpdate = "UPDATE"
	OpDelete = "DELETE"
)

// Line is one parsed preview line (CONTRACT.md, Approvals). Key, Old and Set
// keep the person's column names and values exactly as Postgres returned
// them. A redacted line has only Op, Table, RowHash and Cascaded.
type Line struct {
	Op       string          `json:"op"`
	Key      json.RawMessage `json:"key,omitempty"`
	Old      json.RawMessage `json:"old,omitempty"`
	Set      json.RawMessage `json:"set,omitempty"`
	Table    string          `json:"table"`
	Cascaded bool            `json:"cascaded"`
	Redacted bool            `json:"redacted,omitempty"`
	RowHash  string          `json:"rowHash,omitempty"`
}

// ParseLine parses one preview line for display.
func ParseLine(text string) (Line, error) {
	var l Line
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Line{}, invalid("preview line: %v", err)
	}
	switch l.Op {
	case OpInsert, OpUpdate, OpDelete:
	default:
		return Line{}, invalid("preview line op %q", l.Op)
	}
	if l.Table == "" {
		return Line{}, invalid("preview line without a table")
	}
	return l, nil
}
