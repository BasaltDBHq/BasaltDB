package ledger

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/pkg/wiretime"
)

// ActorKindAgent is the actor kind of every change an agent made.
const ActorKindAgent = "AGENT"

// Record is the wire change record (CONTRACT.md "The change record"), one
// per action, with the rows it wrote. basalt log --json and the MCP
// run_history tool both render it.
type Record struct {
	ChangeID     string          `json:"changeId"`
	At           string          `json:"at"`
	Actor        RecordActor     `json:"actor"`
	Intent       string          `json:"intent,omitempty"`
	Target       RecordTarget    `json:"target"`
	Op           string          `json:"op,omitempty"`
	Statement    string          `json:"statement,omitempty"`
	Params       json.RawMessage `json:"params,omitempty"`
	DurationMs   *int            `json:"durationMs,omitempty"`
	Rows         int             `json:"rows"`
	CascadedRows int             `json:"cascadedRows"`
	Status       string          `json:"status"`
	Reason       *RecordReason   `json:"reason,omitempty"`
	RowChanges   []RecordRow     `json:"rowChanges"`
	// BasedOn is set when the change wrote exactly one non-cascaded row
	// and the run had read it (M1.5).
	BasedOn *RecordBasedOn `json:"basedOn,omitempty"`
	// RevertID is set on a revert's own record (op REVERT, M3).
	RevertID string `json:"revertId,omitempty"`
	// RevertedBy lists the revert changes that restored rows of this
	// change; status is REVERTED only when all its rows were restored.
	RevertedBy []string `json:"revertedBy,omitempty"`
	// LargeValues names the statement or params left out of an agent's read
	// (CONTRACT.md, Large values); absent on the person's.
	LargeValues []largevalue.Entry `json:"largeValues,omitempty"`
}

// RecordBasedOn is the version of a row the run read before writing it.
type RecordBasedOn struct {
	Version  string `json:"version"`
	ChangeID string `json:"changeId,omitempty"`
}

// RecordActor is who made the change.
type RecordActor struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	RunID  string `json:"runId,omitempty"`
	TaskID string `json:"taskId,omitempty"`
}

// RecordTarget is the table the action named first.
type RecordTarget struct {
	Table string `json:"table,omitempty"`
}

// RecordReason is why a REFUSED action was refused: a tool error code.
type RecordReason struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// RecordRow is one row the action wrote, cascades included.
type RecordRow struct {
	Table      string         `json:"table"`
	Op         string         `json:"op"`
	Key        map[string]any `json:"key"`
	Before     map[string]any `json:"before"`
	After      map[string]any `json:"after"`
	Cascaded   bool           `json:"cascaded"`
	Redacted   bool           `json:"redacted"`
	Pruned     bool           `json:"pruned"`
	BasedOn    *RecordBasedOn `json:"basedOn,omitempty"`
	BlindWrite bool           `json:"blindWrite,omitempty"`
	// LargeValues names the values of this row left out of an agent's read.
	LargeValues []largevalue.Entry `json:"largeValues,omitempty"`
	// leftOut are the JSON names of the images left out whole: absent from
	// the row, never null.
	leftOut []string
}

// recordRowFields is RecordRow without its MarshalJSON.
type recordRowFields RecordRow

// MarshalJSON leaves out the images left out whole; a row with none
// marshals as its fields.
func (r RecordRow) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(recordRowFields(r))
	if err != nil || len(r.leftOut) == 0 {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, name := range r.leftOut {
		delete(fields, name)
	}
	return json.Marshal(fields)
}

// RecordFromDomain maps a change and its rows to the wire record.
func RecordFromDomain(ch Change, rows []RowChange) Record {
	rec := Record{
		ChangeID: ch.ID.String(), At: ch.At.UTC().Format(time.RFC3339),
		Actor:  RecordActor{Kind: actorKind(ch.ActorKind), Name: ch.Agent},
		Intent: ch.Intent, Target: RecordTarget{Table: ch.Table}, Op: ch.Op, Statement: ch.Statement,
		Params: ch.Params, DurationMs: ch.DurationMs, Rows: ch.Rows, CascadedRows: ch.CascadedRows,
		Status: ch.Status, RowChanges: make([]RecordRow, 0, len(rows)), LargeValues: ch.LargeValues,
	}
	if ch.RunID.Valid {
		rec.Actor.RunID = ch.RunID.UUID.String()
	}
	if ch.TaskID.Valid {
		rec.Actor.TaskID = ch.TaskID.UUID.String()
	}
	if ch.Code != "" {
		rec.Reason = &RecordReason{Code: ch.Code, Message: ch.Reason}
	}
	if ch.RevertID.Valid {
		rec.RevertID = ch.RevertID.UUID.String()
	}
	for _, id := range ch.RevertedBy {
		rec.RevertedBy = append(rec.RevertedBy, id.String())
	}
	direct := 0
	for _, r := range rows {
		row := RecordRow{
			Table: r.Table, Op: r.Op, Key: wiretime.Map(r.Key), Before: wiretime.Map(r.Before), After: wiretime.Map(r.After),
			Cascaded: r.Cascaded, Redacted: r.Redacted, Pruned: r.Pruned,
			BasedOn: basedOnFromDomain(r.BasedOn), BlindWrite: r.BlindWrite,
			LargeValues: r.LargeValues, leftOut: leftOutImages(r),
		}
		rec.RowChanges = append(rec.RowChanges, row)
		if !r.Cascaded {
			direct++
			rec.BasedOn = row.BasedOn
		}
	}
	if direct != 1 {
		rec.BasedOn = nil
	}
	return rec
}

func basedOnFromDomain(b *BasedOn) *RecordBasedOn {
	if b == nil {
		return nil
	}
	out := &RecordBasedOn{Version: b.Version}
	if b.ChangeID != uuid.Nil {
		out.ChangeID = b.ChangeID.String()
	}
	return out
}

// actorKind defaults to AGENT for records read without the M3 column.
func actorKind(kind string) string {
	if kind == "" {
		return ActorKindAgent
	}
	return kind
}

// leftOutImages are the JSON names of r's images left out whole.
func leftOutImages(r RowChange) []string {
	var out []string
	for _, img := range []struct {
		name string
		out  bool
	}{{"key", r.KeyLeftOut}, {"before", r.BeforeLeftOut}, {"after", r.AfterLeftOut}} {
		if img.out {
			out = append(out, img.name)
		}
	}
	return out
}
