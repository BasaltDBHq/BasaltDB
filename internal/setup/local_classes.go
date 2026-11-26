package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// The column labels of an install of a real database (CONTRACT.md, The
// install of a real database; the rules are the connect page's).

const (
	// CodeClassesChanged: a column's class stored now is not the one the
	// person saw, or the column is gone.
	CodeClassesChanged = "CLASSES_CHANGED"

	maxColumnClasses = 500
	// maxColumns bounds the columns a check lists and samples.
	maxColumns = 500
	// sampleChars cuts each sampled value before it is scored.
	sampleChars = 256
	// sampleBudget is how long one check samples in all.
	sampleBudget = 30 * time.Second
	// sampleStatementTimeout bounds one column's read.
	sampleStatementTimeout = 5 * time.Second
)

// Label is a class with its entity type and phone region.
type Label struct {
	Class       string `json:"class"`
	EntityType  string `json:"entityType,omitempty"`
	PhoneRegion string `json:"phoneRegion,omitempty"`
}

// ColumnClass is a class the person set, with the class the column had when
// it was shown.
type ColumnClass struct {
	Table       string `json:"table"`
	Column      string `json:"column"`
	Class       string `json:"class"`
	EntityType  string `json:"entityType,omitempty"`
	PhoneRegion string `json:"phoneRegion,omitempty"`
	Was         Label  `json:"was"`
}

func (c ColumnClass) label() guardmodel.Label {
	return guardmodel.Label{Class: c.Class, EntityType: c.EntityType, PhoneRegion: c.PhoneRegion}
}

func (l Label) guard() guardmodel.Label {
	return guardmodel.Label{Class: l.Class, EntityType: l.EntityType, PhoneRegion: l.PhoneRegion}
}

// ColumnInfo is a column of a picked table. The suggestion fields come from
// the classifier and are absent when the column was not sampled.
type ColumnInfo struct {
	Table               string `json:"table"`
	Column              string `json:"column"`
	DataType            string `json:"dataType"`
	Class               string `json:"class"`
	EntityType          string `json:"entityType,omitempty"`
	PhoneRegion         string `json:"phoneRegion,omitempty"`
	SuggestedClass      string `json:"suggestedClass,omitempty"`
	SuggestedEntityType string `json:"suggestedEntityType,omitempty"`
	SuggestedRegion     string `json:"suggestedPhoneRegion,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

// hasRealFields: the request names something only an install of a real
// database takes.
func (r Request) hasRealFields() bool {
	return r.Schemas != nil || r.Tables != nil || r.ColumnClasses != nil || r.RestPublic || r.TrustRoot != ""
}

// checkClasses applies the shape rules of the labels, before anything
// connects: at most 500, each in a picked table, each column once, a class
// the page sets and a class the column can have now.
func checkClasses(req Request, picks []TablePick) error {
	if len(req.ColumnClasses) == 0 && !req.RestPublic {
		return nil
	}
	bad := func(why string) error {
		return refuse(CodeAnswersInvalid, "The column labels are not valid: "+why+". Nothing changed.")
	}
	if picks == nil {
		return bad("pick the tables first")
	}
	if len(req.ColumnClasses) > maxColumnClasses {
		return bad("more than 500 columns")
	}
	seen := map[[2]string]bool{}
	for _, c := range req.ColumnClasses {
		key := [2]string{c.Table, c.Column}
		switch {
		case !slices.ContainsFunc(picks, func(p TablePick) bool { return p.Table == c.Table }):
			return bad("a column of a table the agent does not get")
		case seen[key]:
			return bad("a column given twice")
		case !PlainColumn(c.Column) || !guardmodel.ValidLabel(c.label()) || !guardmodel.ValidWas(c.Was.guard()):
			return bad("a class, entity type or phone region the page does not set")
		}
		seen[key] = true
	}
	return nil
}

// classesKey is the labels as the challenge binds them: a hash of the
// sorted entries and the restPublic flag, empty when there are none.
func classesKey(req Request) string {
	if len(req.ColumnClasses) == 0 && !req.RestPublic {
		return ""
	}
	parts := make([]string, len(req.ColumnClasses))
	for i, c := range req.ColumnClasses {
		parts[i] = strings.Join([]string{c.Table, c.Column, c.Class, c.EntityType, c.PhoneRegion, c.Was.Class, c.Was.EntityType, c.Was.PhoneRegion}, "\x1f")
	}
	slices.Sort(parts)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%t\x1e%s", req.RestPublic, strings.Join(parts, "\x1e"))))
	return hex.EncodeToString(sum[:])
}

// labelsSQL is the text the check's SQL carries for the labels: what the
// run writes, in words, since it is data and not a statement list.
func labelsSQL(req Request) string {
	n := len(req.ColumnClasses)
	switch {
	case n == 0 && !req.RestPublic:
		return ""
	case req.RestPublic:
		return fmt.Sprintf("\n-- column labels: %d set as chosen, and PUBLIC for every other column of the picked tables with no class, written to basalt_meta.pii_columns\n", n)
	}
	return fmt.Sprintf("\n-- column labels: %d set as chosen, written to basalt_meta.pii_columns\n", n)
}

// writeLabels writes the person's labels in the run's transaction, after
// the grants: CLASSES_CHANGED, nothing changed, when a column's class is
// not the one the person saw. Its tables are the picks, not the role's
// grants (pkg/setup's writeLabels takes those): the person labels only the
// columns this page showed, and a role finished after an interrupted run
// can hold grants beyond the picks, whose columns restPublic must not mark.
func (s *LocalService) writeLabels(ctx context.Context, tx Tx, names guardmodel.Names, picks []TablePick, req Request, now time.Time) (int, error) {
	if len(req.ColumnClasses) == 0 && !req.RestPublic {
		return 0, nil
	}
	changes := make([]guardmodel.LabelChange, len(req.ColumnClasses))
	for i, c := range req.ColumnClasses {
		changes[i] = guardmodel.LabelChange{Table: c.Table, Column: c.Column, Label: c.label(), Was: c.Was.guard()}
	}
	tables := make([]string, len(picks))
	for i, p := range picks {
		tables[i] = p.Table
	}
	n, err := s.be.WriteLabels(ctx, tx.Port(), names, tables, changes, req.RestPublic, now)
	if errors.Is(err, guardmodel.ErrClassesChanged) {
		return 0, refuse(CodeClassesChanged, "A column's label changed since the page showed it (someone classified it, or the column is gone), so nothing changed. Read the labels again.")
	}
	if err != nil {
		return 0, s.setupFailed("write the labels", err)
	}
	return n, nil
}

// columns lists the columns of the picked tables, at most 500, with the
// class each has now and, for a column whose sample could be read in time,
// the classifier's suggestion. A failed listing fails the check (the person
// must see the columns a label or restPublic covers); a failed sample or key
// read only leaves a column without a suggestion.
func (s *LocalService) columns(ctx context.Context, conn Conn, j job) ([]ColumnInfo, bool, error) {
	tables := make([]string, len(j.picks))
	for i, p := range j.picks {
		tables[i] = p.Table
	}
	// One more than the cap, so a longer list is known.
	listed, err := s.be.ListColumns(ctx, conn.Port(), tables, maxColumns+1)
	if err != nil {
		return nil, false, err
	}
	var cols []ColumnInfo
	for _, c := range listed {
		cols = append(cols, ColumnInfo{Table: c.Namespace + "." + c.Resource, Column: c.Name, DataType: c.DataType})
	}
	more := len(cols) > maxColumns
	if more {
		cols, listed = cols[:maxColumns], listed[:maxColumns]
	}
	labels, err := s.be.ReadLabels(ctx, conn.Port(), guardmodel.Names{Prefix: s.opts.Prefix}, tables)
	if err != nil {
		return nil, false, err
	}
	stored := map[[2]string]guardmodel.Label{}
	for _, l := range labels {
		stored[[2]string{l.Table, l.Column}] = l.Label
	}
	out := make([]ColumnInfo, len(cols))
	for i, c := range cols {
		out[i] = c
		l, ok := stored[[2]string{c.Table, c.Column}]
		if !ok {
			l = guardmodel.Label{Class: guardmodel.ClassUnclassified}
		}
		out[i].Class, out[i].EntityType, out[i].PhoneRegion = l.Class, l.EntityType, l.PhoneRegion
	}
	s.suggest(ctx, conn, listed, out)
	return out, more, nil
}

// suggest samples each listed column and puts the classifier's suggestion
// into out, at the same index. The listed columns carry the schema and
// table names apart, as the catalog gave them: a joined name is never split
// again, since a schema name may hold a dot. Each value is cut to sampleChars characters, the whole sampling
// stops after sampleBudget, and a column whose sample fails or runs out of
// time gets no suggestion. The values stay in memory and are dropped as
// each column is scored.
func (s *LocalService) suggest(ctx context.Context, conn Conn, listed []piistore.Column, out []ColumnInfo) {
	// A failed catalog read leaves the columns' keys unknown; each still
	// carries its kind, so the check goes on.
	cc, _ := s.be.PIIColumns(ctx, conn.Port(), listed)
	sctx, cancel := context.WithTimeout(ctx, sampleBudget)
	defer cancel()
	read := s.be.PIISampler(conn.Port(), sampleStatementTimeout, sampleChars)
	if s.opts.SampleColumn != nil {
		read = func(ctx context.Context, col piistore.Column) (piistore.Sample, error) {
			return s.opts.SampleColumn(ctx, conn, col)
		}
	}
	failed := map[string]bool{}
	// A failed or timed-out sample is not an error of the check: the column
	// gets no suggestion, and the driver's message (which can quote a value)
	// is dropped.
	unsampled := func(col piistore.Column) piistore.Sample {
		failed[col.FullName()] = true
		return piistore.Sample{Unavailable: piistore.UnavailableTimeout}
	}
	sample := func(_ context.Context, col piistore.Column) (piistore.Sample, error) {
		if sctx.Err() != nil {
			return unsampled(col), nil //nolint:nilerr // the driver's message can quote a value; the column gets no suggestion
		}
		smp, err := read(sctx, col)
		readable := err == nil && smp.Unavailable == ""
		if !readable {
			return unsampled(col), nil
		}
		return smp, nil
	}
	results, err := s.be.SuggestColumns(sctx, cc, sample)
	if err != nil {
		return
	}
	for i, r := range results {
		if failed[r.Column.FullName()] {
			continue
		}
		out[i].SuggestedClass, out[i].SuggestedEntityType = r.Class, r.EntityType
		out[i].SuggestedRegion, out[i].Reason = r.PhoneRegion, r.Reason
	}
}
