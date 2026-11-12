package classify

import (
	"encoding/hex"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Why a column is shown in the review (CONTRACT.md, basalt classify,
// status): the first that applies.
const (
	StatusNew               = "NEW"
	StatusUnclassified      = "UNCLASSIFIED"
	StatusTypeChanged       = "TYPE_CHANGED"
	StatusNeedsReview       = "NEEDS_REVIEW"
	StatusSuggestionDiffers = "SUGGESTION_DIFFERS"
	StatusUnchanged         = "UNCHANGED"
)

// ReviewColumn is one column of the review.
type ReviewColumn struct {
	Result
	// Stored is the column's row in pii_columns, nil when it has none.
	Stored *guard.PIIColumn
	Status string
}

// Confirmed reports whether a person gave the column a class already.
func (c ReviewColumn) Confirmed() bool {
	return c.Stored != nil && c.Stored.Class != guard.ClassUnclassified
}

// ReviewTable is the review of one table, its columns in table order.
type ReviewTable struct {
	Table   string
	Columns []ReviewColumn
}

// StatusOf is why col would be shown, given its stored row (nil for none).
func StatusOf(stored *guard.PIIColumn, col Column, s Suggestion) string {
	switch {
	case stored == nil:
		return StatusNew
	case stored.Class == guard.ClassUnclassified:
		return StatusUnclassified
	case stored.DataType != col.DataType:
		return StatusTypeChanged
	case stored.NeedsReview:
		return StatusNeedsReview
	case stored.Class != s.Class || stored.EntityType != s.EntityType:
		return StatusSuggestionDiffers
	}
	return StatusUnchanged
}

// BuildReview groups results by table, in their order, with their stored
// rows. all keeps UNCHANGED columns (--review=all); otherwise only the
// columns that need a person are shown.
func BuildReview(results []Result, stored map[guard.ColumnKey]guard.PIIColumn, all bool) []ReviewTable {
	var out []ReviewTable
	for _, r := range results {
		rc := ReviewColumn{Result: r}
		if row, ok := stored[guard.ColumnKey{Schema: r.Column.Schema, Table: r.Column.Table, Column: r.Column.Name}]; ok {
			rc.Stored = &row
		}
		rc.Status = StatusOf(rc.Stored, r.Column, r.Suggestion)
		if rc.Status == StatusUnchanged && !all {
			continue
		}
		table := r.Column.QualifiedTable()
		if len(out) == 0 || out[len(out)-1].Table != table {
			out = append(out, ReviewTable{Table: table})
		}
		last := &out[len(out)-1]
		last.Columns = append(last.Columns, rc)
	}
	return out
}

// Decision is the class a column gets in this run.
type Decision struct {
	Class, EntityType, PhoneRegion string
	// NeedsReview stays set when the class was taken without a person
	// looking at it (--yes on a needs-review column).
	NeedsReview bool
}

// Suggested is the suggestion as a decision, for a person who accepted it.
func (c ReviewColumn) Suggested() Decision {
	s := c.Suggestion
	return Decision{Class: s.Class, EntityType: s.EntityType, PhoneRegion: s.PhoneRegion}
}

// Protected is what --yes takes: the suggestion, flagged for review when it
// is, unless the class a person confirmed earlier protects more, which then
// stays. An unattended run never lowers a column's protection.
func (c ReviewColumn) Protected() Decision {
	if c.Confirmed() && Rank(c.Stored.Class) > Rank(c.Suggestion.Class) {
		st := c.Stored
		return Decision{Class: st.Class, EntityType: st.EntityType, PhoneRegion: st.PhoneRegion, NeedsReview: st.NeedsReview}
	}
	d := c.Suggested()
	d.NeedsReview = c.Suggestion.NeedsReview
	return d
}

// Rows are the pii_columns rows a run writes: every decided column with its
// decision (stamped confirmed), and every shown, undecided column that has
// no class yet as UNCLASSIFIED with its suggestion. A shown column a person
// confirmed earlier and did not decide on now keeps its row as it is
// (owner decision OR-1: confirmed classes survive).
func Rows(tables []ReviewTable, decided map[string]Decision) []guard.PIIColumn {
	var out []guard.PIIColumn
	for _, t := range tables {
		for _, c := range t.Columns {
			s := c.Suggestion
			row := guard.PIIColumn{
				Schema: c.Column.Schema, Table: c.Column.Table, Column: c.Column.Name, DataType: c.Column.DataType,
				SuggestedClass: s.Class, SuggestedEntityType: s.EntityType, Reason: s.Reason,
			}
			d, ok := decided[c.Column.FullName()]
			switch {
			case ok:
				row.Class, row.EntityType, row.NeedsReview = d.Class, d.EntityType, d.NeedsReview
				if d.EntityType == guard.EntityPhone {
					row.PhoneRegion = d.PhoneRegion
				}
			case c.Confirmed():
				continue
			default:
				row.Class, row.NeedsReview = guard.ClassUnclassified, s.NeedsReview
			}
			out = append(out, row)
		}
	}
	return out
}

// ReviewJSON is the --json review (api/mcp/pii/classify-review.schema.json).
type ReviewJSON struct {
	Fingerprint         string            `json:"fingerprint"`
	PreviousFingerprint string            `json:"previousFingerprint,omitempty"`
	Review              string            `json:"review"`
	DryRun              bool              `json:"dryRun"`
	Written             bool              `json:"written"`
	Tables              []ReviewTableJSON `json:"tables"`
}

// ReviewTableJSON is one table of ReviewJSON.
type ReviewTableJSON struct {
	Table   string             `json:"table"`
	Columns []ReviewColumnJSON `json:"columns"`
}

// ReviewColumnJSON is one column of ReviewJSON. Class, EntityType and
// PhoneRegion are what is stored once the run is over.
type ReviewColumnJSON struct {
	Column              string     `json:"column"`
	DataType            string     `json:"dataType"`
	Status              string     `json:"status"`
	Class               string     `json:"class"`
	EntityType          string     `json:"entityType,omitempty"`
	SuggestedClass      string     `json:"suggestedClass"`
	SuggestedEntityType string     `json:"suggestedEntityType,omitempty"`
	Reason              string     `json:"reason"`
	NeedsReview         bool       `json:"needsReview"`
	PhoneRegion         string     `json:"phoneRegion,omitempty"`
	Check               *CheckJSON `json:"check,omitempty"`
}

// CheckJSON is a column's --check result.
type CheckJSON struct {
	Sampled           int `json:"sampled"`
	RoundTripFailures int `json:"roundTripFailures"`
	CommonWordRule    int `json:"commonWordRule"`
}

// ReviewMeta is what ReviewJSON carries beside the tables.
type ReviewMeta struct {
	Fingerprint, Previous []byte
	Review                string
	DryRun, Written       bool
}

// JSONFromReview maps the review to its JSON form. rows are the rows the
// run wrote (nil when it wrote none), checks the --check results.
func JSONFromReview(tables []ReviewTable, meta ReviewMeta, rows []guard.PIIColumn, checks map[string]CheckResult) ReviewJSON {
	written := map[string]guard.PIIColumn{}
	for _, r := range rows {
		written[r.Schema+"."+r.Table+"."+r.Column] = r
	}
	out := ReviewJSON{
		Fingerprint: hex.EncodeToString(meta.Fingerprint), Review: meta.Review,
		DryRun: meta.DryRun, Written: meta.Written, Tables: []ReviewTableJSON{},
	}
	if meta.Previous != nil {
		out.PreviousFingerprint = hex.EncodeToString(meta.Previous)
	}
	for _, t := range tables {
		tj := ReviewTableJSON{Table: t.Table}
		for _, c := range t.Columns {
			s := c.Suggestion
			cj := ReviewColumnJSON{
				Column: c.Column.Name, DataType: c.Column.DataType, Status: c.Status,
				Class: guard.ClassUnclassified, SuggestedClass: s.Class, SuggestedEntityType: s.EntityType,
				Reason: s.Reason, NeedsReview: s.NeedsReview,
			}
			now := c.Stored
			if row, ok := written[c.Column.FullName()]; ok {
				now = &row
			}
			if now != nil {
				cj.Class, cj.EntityType, cj.PhoneRegion = now.Class, now.EntityType, now.PhoneRegion
			}
			if cj.PhoneRegion == "" && s.EntityType == guard.EntityPhone {
				cj.PhoneRegion = s.PhoneRegion
			}
			if cj.EntityType != guard.EntityPhone && s.EntityType != guard.EntityPhone {
				cj.PhoneRegion = ""
			}
			if ck, ok := checks[c.Column.FullName()]; ok {
				cj.Check = &CheckJSON{Sampled: ck.Sampled, RoundTripFailures: ck.RoundTripFailures, CommonWordRule: ck.CommonWordRule}
			}
			tj.Columns = append(tj.Columns, cj)
		}
		out.Tables = append(out.Tables, tj)
	}
	return out
}
