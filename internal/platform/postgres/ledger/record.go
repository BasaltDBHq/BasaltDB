package ledger

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/wiretime"
)

// ActorKindAgent is the actor kind of every change an agent made.
const ActorKindAgent = "AGENT"

// Record is the wire change record (CONTRACT.md "The change record"), one
// per action, with the rows it wrote. basalt log --json and the MCP
// run_history tool both render it.
type Record struct {
	ChangeID string      `json:"changeId"`
	At       string      `json:"at"`
	Actor    RecordActor `json:"actor"`
	Intent   string      `json:"intent,omitempty"`
	// Resource is the request's own resource (schema.table in Postgres),
	// and Shape its kind of data: both absent when the action named none.
	Resource     string         `json:"resource,omitempty"`
	Shape        string         `json:"shape,omitempty"`
	Op           string         `json:"op"`
	Store        RecordStore    `json:"store"`
	Request      *RecordRequest `json:"request,omitempty"`
	DurationMs   *int           `json:"durationMs,omitempty"`
	Rows         int            `json:"rows"`
	CascadedRows int            `json:"cascadedRows"`
	Status       string         `json:"status"`
	Reason       *RecordReason  `json:"reason,omitempty"`
	RowChanges   []RecordRow    `json:"rowChanges"`
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

// RecordStore is the record's store part (CONTRACT.md, Stores, What every
// store writes): the store's kind and its own word for the request's
// operation, absent on REVERT and on an OTHER the store gave no command for.
type RecordStore struct {
	Kind string `json:"kind"`
	Verb string `json:"verb,omitempty"`
}

// RecordRequest is the request by family (CONTRACT.md, Stores, Request
// families): for SQL the statement and the values bound to it, either
// absent when it is left out as a large value.
type RecordRequest struct {
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params,omitempty"`
	Statement string          `json:"statement,omitempty"`
}

// RecordReason is why a REFUSED action was refused: a tool error code.
type RecordReason struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// RecordRow is one row the action wrote, cascades included.
type RecordRow struct {
	Resource   string         `json:"resource"`
	Shape      string         `json:"shape"`
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
func RecordFromDomain(ch action.Change, rows []action.RowChange) Record {
	rec := Record{
		ChangeID: ch.ID.String(), At: ch.At.UTC().Format(time.RFC3339),
		Actor:  RecordActor{Kind: actorKind(ch.ActorKind), Name: ch.Agent},
		Intent: ch.Intent, Op: ch.Op, Store: RecordStore{Kind: string(action.StorePostgres), Verb: ch.Verb},
		Request: requestOf(ch), DurationMs: ch.DurationMs, Rows: ch.Rows, CascadedRows: ch.CascadedRows,
		Status: ch.Status, RowChanges: make([]RecordRow, 0, len(rows)), LargeValues: ch.LargeValues,
	}
	if ch.Table != "" {
		rec.Resource, rec.Shape = ch.Table, approval.ShapeRecord
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
			Resource: r.Table, Shape: approval.ShapeRecord, Op: r.Op, Key: wiretime.Map(r.Key), Before: wiretime.Map(r.Before), After: wiretime.Map(r.After),
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

// requestOf is ch's request: its statement and params, nil when it has
// neither and none was left out as a large value (a revert's own record).
func requestOf(ch action.Change) *RecordRequest {
	if ch.Statement == "" && ch.Params == nil && len(ch.LargeValues) == 0 {
		return nil
	}
	return &RecordRequest{Kind: approval.RequestSQL, Params: ch.Params, Statement: ch.Statement}
}

func basedOnFromDomain(b *action.BasedOn) *RecordBasedOn {
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
func leftOutImages(r action.RowChange) []string {
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
