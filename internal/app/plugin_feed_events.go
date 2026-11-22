package app

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// The CloudEvents envelope of a feed/1 event (CONTRACT.md, Wire format and
// Notifier messages).
const (
	cloudEventsSpecVersion = "1.0"
	feedDataContentType    = "application/json"
	feedTypePrefix         = "dev.basaltdb."
	feedTypeSkipped        = feedTypePrefix + "feed.skipped"
	// feedTableMaxRunes is feed.schema.json's longest table.
	feedTableMaxRunes = 300
	// feedTimeLayout is RFC 3339 UTC with Z, fractional seconds kept when
	// present (at most microseconds, as Postgres stores them).
	feedTimeLayout = "2006-01-02T15:04:05.999999Z"
)

// feedTypes is each ledger kind's event type.
var feedTypes = map[string]string{
	guard.KindChange:          feedTypePrefix + "write.applied",
	guard.KindRefused:         feedTypePrefix + "write.refused",
	guard.KindApprovalPending: feedTypePrefix + "write.held",
	guard.KindApproved:        feedTypePrefix + "approval.signed",
	guard.KindRevertPending:   feedTypePrefix + "revert.prepared",
	guard.KindRevertSigned:    feedTypePrefix + "revert.signed",
	guard.KindReverted:        feedTypePrefix + "revert.applied",
	guard.KindRevertRejected:  feedTypePrefix + "revert.rejected",
}

// feedReasonCodes are the codes of CONTRACT.md, Error codes: a refusal's
// code is sent as reasonCode only when it is one of them.
var feedReasonCodes = map[string]bool{
	"INTENT_REQUIRED": true, "STALE_READ": true, "STATEMENT_REFUSED": true, "ROW_LIMIT_EXCEEDED": true,
	"QUERY_TIMEOUT": true, "APPROVAL_REQUIRED": true, "APPROVAL_EXPIRED": true, "APPROVAL_INVALID": true,
	"REVERT_INVALID": true, "REVERT_EXPIRED": true, "NOTHING_TO_REVERT": true, "PERMISSION_DENIED": true,
	"NOT_FOUND": true, "SQL_ERROR": true, "INVALID_ARGUMENT": true, "UNAVAILABLE": true, "INTERNAL": true,
	"PLUGIN_REFUSED": true,
}

// Operations an event may name.
var (
	writeOps   = []string{"INSERT", "UPDATE", "DELETE"}
	refusedOps = []string{"INSERT", "UPDATE", "DELETE", "OTHER"}
)

// feedEvent is one CloudEvent of feed/1, in its JSON form.
type feedEvent struct {
	SpecVersion     string   `json:"specversion"`
	ID              string   `json:"id"`
	Source          string   `json:"source"`
	Type            string   `json:"type"`
	Time            string   `json:"time,omitempty"`
	Subject         string   `json:"subject"`
	DataContentType string   `json:"datacontenttype"`
	Data            feedData `json:"data"`
}

// feedData is an event's data: installId, seq and agent, and the fields its
// kind carries (CONTRACT.md, Which ledger rows are events). Nothing else
// can be written: there is no field for a value, a statement, an intent or
// a refusal message.
type feedData struct {
	InstallID    string `json:"installId"`
	Seq          int64  `json:"seq"`
	Agent        string `json:"agent"`
	AfterSeq     *int64 `json:"afterSeq,omitempty"`
	ChangeID     string `json:"changeId,omitempty"`
	ApprovalID   string `json:"approvalId,omitempty"`
	RevertID     string `json:"revertId,omitempty"`
	RunID        string `json:"runId,omitempty"`
	TaskID       string `json:"taskId,omitempty"`
	Op           string `json:"op,omitempty"`
	Table        string `json:"table,omitempty"`
	Rows         *int64 `json:"rows,omitempty"`
	CascadedRows *int64 `json:"cascadedRows,omitempty"`
	ReasonCode   string `json:"reasonCode,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// feedEventOf is the event of ledger row r of agent (its name in
// engine.json) in the database of install id install, false when the row
// is not one feed/1 can carry: a kind that is not an event, or a field the
// schema needs that the row does not hold in the form it fixes. Only what
// the row holds at its seq goes in, parsed and written again, never copied
// as text: an id is a UUID, a count a number, a time RFC 3339.
func feedEventOf(install uuid.UUID, agent string, r guard.FeedRow) (feedEvent, bool) {
	typ, ok := feedTypes[r.Kind]
	if !ok || r.Seq <= 0 {
		return feedEvent{}, false
	}
	d := feedData{InstallID: install.String(), Seq: r.Seq, Agent: agent}
	if !fillFeedData(&d, r) {
		return feedEvent{}, false
	}
	return feedEvent{
		SpecVersion:     cloudEventsSpecVersion,
		ID:              install.String() + ":" + strconv.FormatInt(r.Seq, 10),
		Source:          feedSource(install),
		Type:            typ,
		Time:            r.At.UTC().Format(feedTimeLayout),
		Subject:         agent,
		DataContentType: feedDataContentType,
		Data:            d,
	}, true
}

// fillFeedData sets the fields of r's kind, and reports whether every field
// the kind needs is there.
func fillFeedData(d *feedData, r guard.FeedRow) bool {
	var ok bool
	switch r.Kind {
	case guard.KindChange:
		ok = fill(d.setChange(r), d.setRunTask(r), d.setOp(r, writeOps), d.setCounts(r))
		if ok && r.Table != nil {
			d.Table, ok = feedTable(*r.Table)
		}
	case guard.KindRefused:
		ok = fill(d.setChange(r), d.setRunTask(r), d.setOp(r, refusedOps))
		if ok && r.Code != nil && feedReasonCodes[*r.Code] {
			d.ReasonCode = *r.Code
		}
	case guard.KindApprovalPending:
		ok = fill(d.setChange(r), d.setRunTask(r), d.setOp(r, writeOps), d.setHeldRows(r), d.setExpiry(r))
		ok = ok && d.RunID != "" && setID(&d.ApprovalID, r.ApprovalID)
	case guard.KindApproved:
		ok = d.setChange(r) && setID(&d.ApprovalID, r.ApprovalID)
	case guard.KindRevertSigned, guard.KindReverted:
		ok = d.setChange(r) && setID(&d.RevertID, r.RevertID)
	case guard.KindRevertPending, guard.KindRevertRejected:
		ok = setID(&d.RevertID, r.RevertID)
	}
	return ok
}

func fill(oks ...bool) bool {
	for _, ok := range oks {
		if !ok {
			return false
		}
	}
	return true
}

func (d *feedData) setChange(r guard.FeedRow) bool {
	if !r.ChangeID.Valid {
		return false
	}
	d.ChangeID = r.ChangeID.UUID.String()
	return true
}

// setRunTask sets runId and taskId when the row holds them.
func (d *feedData) setRunTask(r guard.FeedRow) bool {
	return optionalID(&d.RunID, r.RunID) && optionalID(&d.TaskID, r.TaskID)
}

func (d *feedData) setOp(r guard.FeedRow, allowed []string) bool {
	if r.Op == nil || !slices.Contains(allowed, *r.Op) {
		return false
	}
	d.Op = *r.Op
	return true
}

// setCounts sets a write's rows and cascadedRows; a row that holds none
// changed none.
func (d *feedData) setCounts(r guard.FeedRow) bool {
	rows, ok := count(r.Rows, 0)
	cascaded, ok2 := count(r.CascadedRows, 0)
	if !ok || !ok2 {
		return false
	}
	d.Rows, d.CascadedRows = &rows, &cascaded
	return true
}

// setHeldRows sets a held write's rows: at least one.
func (d *feedData) setHeldRows(r guard.FeedRow) bool {
	if r.Rows == nil {
		return false
	}
	rows, ok := count(r.Rows, 1)
	if !ok {
		return false
	}
	d.Rows = &rows
	return true
}

func (d *feedData) setExpiry(r guard.FeedRow) bool {
	if r.ExpiresAt == nil {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, *r.ExpiresAt)
	if err != nil {
		return false
	}
	d.ExpiresAt = t.UTC().Format(feedTimeLayout)
	return true
}

// setID sets a required id.
func setID(dst *string, v *string) bool {
	return v != nil && optionalID(dst, v)
}

// optionalID sets an id when v holds one; a v that is not a UUID fails.
func optionalID(dst *string, v *string) bool {
	if v == nil {
		return true
	}
	id, err := uuid.Parse(*v)
	if err != nil {
		return false
	}
	*dst = id.String()
	return true
}

// count is a row count from v, nil as 0, at least lowest.
func count(v *string, lowest int64) (int64, bool) {
	if v == nil {
		return 0, lowest == 0
	}
	n, err := strconv.ParseInt(*v, 10, 64)
	return n, err == nil && n >= lowest
}

// feedTable is the statement's own table as Postgres writes its name, each
// control character replaced by U+FFFD (CONTRACT.md, table is the
// database's text). False when it is empty or longer than the schema
// allows.
func feedTable(name string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(name, string(utf8.RuneError)))
	n := utf8.RuneCountInString(clean)
	return clean, n >= 1 && n <= feedTableMaxRunes
}

// feedSource is the events' source: the database's guard install.
func feedSource(install uuid.UUID) string { return "urn:uuid:" + install.String() }

// skippedEvent is the skipped-ahead marker: retention deleted rows after
// the cursor (afterSeq) before they were delivered; the agent's events up
// to seq may be gone.
func skippedEvent(install uuid.UUID, agent string, afterSeq, seq int64) feedEvent {
	after := afterSeq
	return feedEvent{
		SpecVersion:     cloudEventsSpecVersion,
		ID:              install.String() + ":skipped:" + strconv.FormatInt(afterSeq, 10) + ":" + strconv.FormatInt(seq, 10),
		Source:          feedSource(install),
		Type:            feedTypeSkipped,
		Subject:         agent,
		DataContentType: feedDataContentType,
		Data:            feedData{InstallID: install.String(), Seq: seq, Agent: agent, AfterSeq: &after},
	}
}

// feedBatch is events as a CloudEvents JSON batch, encoded as the
// transports encode it (protocol.Marshal), and their seqs.
func feedBatch(events []feedEvent) (json.RawMessage, []int64, error) {
	seqs := make([]int64, 0, len(events))
	for _, e := range events {
		seqs = append(seqs, e.Data.Seq)
	}
	raw, err := pluginproto.Marshal(events)
	return raw, seqs, err
}
