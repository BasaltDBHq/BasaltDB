package approval

import (
	"fmt"
	"sort"
	"strings"
)

// Group is the rows of one table and operation in a held write.
type Group struct {
	Table string
	Op    string
	Rows  int
	// Hidden is set when the lines are redacted: the counts are exact, the
	// values are not shown.
	Hidden bool
}

// Summary counts a held write's rows from its bound preview lines: the rows
// the statement changes and the rows it changes by cascade (owner decision,
// Nov 12: cascades are never left to a scroll through the rows).
type Summary struct {
	// Direct groups in the order of the lines.
	Direct []Group
	// Cascaded groups, most rows first, then by table and operation.
	Cascaded []Group
}

// Summarize counts parsed preview lines.
func Summarize(lines []Line) Summary {
	var s Summary
	for _, l := range lines {
		if l.Cascaded {
			s.Cascaded = addRow(s.Cascaded, l)
			continue
		}
		s.Direct = addRow(s.Direct, l)
	}
	sort.SliceStable(s.Cascaded, func(i, j int) bool {
		a, b := s.Cascaded[i], s.Cascaded[j]
		if a.Rows != b.Rows {
			return a.Rows > b.Rows
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		return a.Op < b.Op
	})
	return s
}

// SummarizeText parses preview line text and counts it.
func SummarizeText(texts []string) (Summary, error) {
	lines := make([]Line, 0, len(texts))
	for _, t := range texts {
		l, err := ParseLine(t)
		if err != nil {
			return Summary{}, err
		}
		lines = append(lines, l)
	}
	return Summarize(lines), nil
}

func addRow(groups []Group, l Line) []Group {
	for i := range groups {
		if groups[i].Table == l.Table && groups[i].Op == l.Op {
			groups[i].Rows++
			groups[i].Hidden = groups[i].Hidden || l.Redacted
			return groups
		}
	}
	return append(groups, Group{Table: l.Table, Op: l.Op, Rows: 1, Hidden: l.Redacted})
}

// CascadedRows is the number of rows changed by cascade.
func (s Summary) CascadedRows() int {
	n := 0
	for _, g := range s.Cascaded {
		n += g.Rows
	}
	return n
}

// Verbs for the headline, by operation.
var (
	verbs     = map[string]string{OpInsert: "insert", OpUpdate: "update", OpDelete: "delete"}
	pastVerbs = map[string]string{OpInsert: "inserted", OpUpdate: "updated", OpDelete: "deleted"}
)

const hiddenMark = " [values hidden]"

// Headline states the held write in one line, cascades explicit, e.g.
// "Delete 1 row in public.customers + 30 cascaded rows (public.invoices 28,
// public.payments 2 [values hidden])". A cascaded group whose operation is
// not the statement's says so ("public.lead_owner 1 updated"). The approval
// page builds the same text (web/lib/summary.js).
func (s Summary) Headline() string {
	parts := make([]string, 0, len(s.Direct))
	for _, g := range s.Direct {
		parts = append(parts, fmt.Sprintf("%s %s in %s%s", verbs[g.Op], plural(g.Rows, "row"), g.Table, hidden(g)))
	}
	text := capitalize(strings.Join(parts, ", "))
	if len(s.Cascaded) == 0 {
		return text
	}
	mainOp := ""
	if len(s.Direct) > 0 {
		mainOp = s.Direct[0].Op
	}
	entries := make([]string, 0, len(s.Cascaded))
	for _, g := range s.Cascaded {
		entry := fmt.Sprintf("%s %d", g.Table, g.Rows)
		if g.Op != mainOp {
			entry += " " + pastVerbs[g.Op]
		}
		entries = append(entries, entry+hidden(g))
	}
	cascade := fmt.Sprintf("%s (%s)", plural(s.CascadedRows(), "cascaded row"), strings.Join(entries, ", "))
	if text == "" {
		return capitalize(cascade)
	}
	return text + " + " + cascade
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func hidden(g Group) string {
	if g.Hidden {
		return hiddenMark
	}
	return ""
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
