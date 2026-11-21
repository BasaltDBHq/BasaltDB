// Package rlspick is the row-level security table picker of basalt init:
// the selection model (tables grouped by schema, all checked by default),
// the list syntax of --agent-rls, and the checklist a person drives at a
// terminal. The model and the parser know nothing about the terminal.
package rlspick

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Entry is one table the agent may be given all rows of.
type Entry struct {
	// Table is schema.table.
	Table string
	// Rows is how many rows the table holds.
	Rows int64
}

// Split returns the schema and the table name of schema.table.
func Split(table string) (schema, name string) {
	schema, name, _ = strings.Cut(table, ".")
	return schema, name
}

// Pattern is one entry of the list syntax: schema.table, or schema.* for
// every table of the schema.
type Pattern struct {
	Schema string
	// Table is empty for schema.*.
	Table string
}

// String is the pattern as written.
func (p Pattern) String() string {
	if p.Table == "" {
		return p.Schema + ".*"
	}
	return p.Schema + "." + p.Table
}

// ParseList parses "us.*,global.user_router". Entries are trimmed; an empty
// entry, or one that is not schema.table or schema.*, is an error.
func ParseList(s string) ([]Pattern, error) {
	var out []Pattern
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		schema, name, ok := strings.Cut(part, ".")
		if !ok || schema == "" || name == "" {
			return nil, fmt.Errorf("%q is not schema.table or schema.*", part)
		}
		p := Pattern{Schema: schema, Table: name}
		if name == "*" {
			p.Table = ""
		}
		out = append(out, p)
	}
	return out, nil
}

// Match returns which entries the patterns select, and the patterns that
// selected none.
func Match(entries []Entry, patterns []Pattern) (picked []bool, unknown []Pattern) {
	picked = make([]bool, len(entries))
	for _, p := range patterns {
		hit := false
		for i, e := range entries {
			schema, name := Split(e.Table)
			if schema == p.Schema && (p.Table == "" || name == p.Table) {
				picked[i] = true
				hit = true
			}
		}
		if !hit {
			unknown = append(unknown, p)
		}
	}
	return picked, unknown
}

// Answer is what a person typed on the piped line.
type Answer struct {
	// All and None are the words all and none; both false means Patterns.
	All, None bool
	Patterns  []Pattern
}

// ErrAnswer is wrapped by ParseAnswer's error.
var ErrAnswer = errors.New("not all, none or a list")

// ParseAnswer parses the piped line: empty or "all" (also "all-rows"),
// "none", or the list syntax.
func ParseAnswer(s string) (Answer, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all", "all-rows":
		return Answer{All: true}, nil
	case "none":
		return Answer{None: true}, nil
	}
	p, err := ParseList(s)
	if err != nil {
		return Answer{}, fmt.Errorf("%w: %w", ErrAnswer, err)
	}
	return Answer{Patterns: p}, nil
}

// Model is the checklist's state: schemas with their tables, every table
// checked, one cursor over the visible rows.
type Model struct {
	groups []*group
	cursor int
}

type group struct {
	schema string
	open   bool
	tables []*item
}

type item struct {
	name, full string
	rows       int64
	checked    bool
}

// New groups entries by schema (schemas and tables sorted by name), checks
// every table and opens the first schema.
func New(entries []Entry) *Model {
	es := append([]Entry(nil), entries...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].Table < es[j].Table })
	m := &Model{}
	var cur *group
	for _, e := range es {
		schema, name := Split(e.Table)
		if cur == nil || cur.schema != schema {
			cur = &group{schema: schema}
			m.groups = append(m.groups, cur)
		}
		cur.tables = append(cur.tables, &item{name: name, full: e.Table, rows: e.Rows, checked: true})
	}
	if len(m.groups) > 0 {
		m.groups[0].open = true
	}
	return m
}

// row is a visible line: a schema (t -1) or one of its tables.
type row struct{ g, t int }

func (m *Model) visible() []row {
	var out []row
	for gi, g := range m.groups {
		out = append(out, row{gi, -1})
		if g.open {
			for ti := range g.tables {
				out = append(out, row{gi, ti})
			}
		}
	}
	return out
}

func (m *Model) at() (row, bool) {
	v := m.visible()
	if len(v) == 0 {
		return row{}, false
	}
	if m.cursor >= len(v) {
		m.cursor = len(v) - 1
	}
	return v[m.cursor], true
}

func (m *Model) moveTo(r row) {
	for i, v := range m.visible() {
		if v == r {
			m.cursor = i
			return
		}
	}
}

// Up moves the cursor one visible row up.
func (m *Model) Up() {
	if m.cursor > 0 {
		m.cursor--
	}
}

// Down moves the cursor one visible row down.
func (m *Model) Down() {
	if m.cursor < len(m.visible())-1 {
		m.cursor++
	}
}

// Open opens the schema under the cursor.
func (m *Model) Open() {
	if r, ok := m.at(); ok {
		m.groups[r.g].open = true
	}
}

// Close closes the schema under the cursor and puts the cursor on it.
func (m *Model) Close() {
	if r, ok := m.at(); ok {
		m.groups[r.g].open = false
		m.moveTo(row{r.g, -1})
	}
}

// Toggle flips the table under the cursor; on a schema row it flips the
// whole schema.
func (m *Model) Toggle() {
	r, ok := m.at()
	if !ok {
		return
	}
	if r.t < 0 {
		m.ToggleSchema()
		return
	}
	t := m.groups[r.g].tables[r.t]
	t.checked = !t.checked
}

// ToggleSchema flips the whole schema under the cursor: all its tables
// checked unless they all are already, then none.
func (m *Model) ToggleSchema() {
	r, ok := m.at()
	if !ok {
		return
	}
	g := m.groups[r.g]
	want := g.state() != all
	for _, t := range g.tables {
		t.checked = want
	}
}

// Clear unchecks every table.
func (m *Model) Clear() {
	for _, g := range m.groups {
		for _, t := range g.tables {
			t.checked = false
		}
	}
}

// Counts is how many tables are checked, of how many.
func (m *Model) Counts() (checked, total int) {
	for _, g := range m.groups {
		for _, t := range g.tables {
			total++
			if t.checked {
				checked++
			}
		}
	}
	return checked, total
}

// Checked lists the checked tables as schema.table, in display order.
func (m *Model) Checked() []string {
	var out []string
	for _, g := range m.groups {
		for _, t := range g.tables {
			if t.checked {
				out = append(out, t.full)
			}
		}
	}
	return out
}

type checkState int

const (
	none checkState = iota
	some
	all
)

func (g *group) state() checkState {
	n := 0
	for _, t := range g.tables {
		if t.checked {
			n++
		}
	}
	switch n {
	case 0:
		return none
	case len(g.tables):
		return all
	}
	return some
}

// Groups describes each schema for a plain listing: "global: 4 tables, 20
// rows" followed by its tables, one line each.
func (m *Model) Groups() []string {
	var out []string
	for _, g := range m.groups {
		var rows int64
		for _, t := range g.tables {
			rows += t.rows
		}
		out = append(out, fmt.Sprintf("%s (%s, %s)", clean(g.schema), plural(int64(len(g.tables)), "table", "tables"), plural(rows, "row", "rows")))
		for _, t := range g.tables {
			out = append(out, fmt.Sprintf("  %s.%s  %s", clean(g.schema), clean(t.name), plural(t.rows, "row", "rows")))
		}
	}
	return out
}
