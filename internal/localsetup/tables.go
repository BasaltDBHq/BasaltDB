package localsetup

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// The tables of an install of a real database (CONTRACT.md, The install of
// a real database).

const (
	// CodeTablesChanged: a picked table is not as the listing showed it.
	CodeTablesChanged = "TABLES_CHANGED"

	AccessWrite = "WRITE"
	AccessRead  = "READ"

	// ChoiceAllRows and ChoiceNone answer a row-level security question.
	ChoiceAllRows = "ALL_ROWS"
	ChoiceNone    = "NONE"

	maxSchemas = 5
	maxTables  = 500

	// unsupportedName is the owner shown for a table whose name cannot be
	// picked.
	unsupportedName = "unsupported name"
)

// plainName is a plain lowercase identifier, as a setup code's tables are.
const plainName = `[a-z_][a-z0-9_]{0,62}`

var (
	plainSchema = regexp.MustCompile(`^` + plainName + `$`)
	plainTable  = regexp.MustCompile(`^` + plainName + `\.` + plainName + `$`)
)

// TablePick is one table the person gave the agent, and how.
type TablePick struct {
	Table  string `json:"table"`
	Access string `json:"access"`
}

// ListedTable is a table the person can pick; CanWrite is false for a table
// without a primary key, which can only be read.
type ListedTable struct {
	Table    string `json:"table"`
	CanWrite bool   `json:"canWrite"`
}

// ExcludedTable is a table that cannot be picked, with the reason shown as
// the owner: the owner's role, or "unsupported name".
type ExcludedTable struct {
	Table string `json:"table"`
	Owner string `json:"owner"`
}

// listing is what a read of the schemas' tables found.
type listing struct {
	tables   []ListedTable
	excluded []ExcludedTable
	more     bool
}

// listSQL reads the ordinary and partitioned tables of the schemas $1 (one
// more than the cap, so a longer list is known). Plain SQL: a catalog read
// squirrel cannot express. Partitions are left out: the agent reaches their
// rows through the partitioned table.
const listSQL = `SELECT n.nspname || '.' || c.relname,
       r.rolname,
       r.rolname = current_user,
       EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p'),
       c.relname ~ '^` + plainName + `$'
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
 WHERE n.nspname = ANY($1)
   AND c.relkind IN ('r', 'p')
   AND NOT c.relispartition
 ORDER BY n.nspname COLLATE "C", c.relname COLLATE "C"
 LIMIT $2`

func readListing(ctx context.Context, q guard.Querier, schemas []string) (listing, error) {
	rows, err := q.Query(ctx, listSQL, schemas, maxTables+1)
	if err != nil {
		return listing{}, err
	}
	defer rows.Close()
	out := listing{tables: []ListedTable{}, excluded: []ExcludedTable{}}
	for rows.Next() {
		var table, owner string
		var mine, keyed, plain bool
		if err := rows.Scan(&table, &owner, &mine, &keyed, &plain); err != nil {
			return listing{}, err
		}
		if len(out.tables)+len(out.excluded) == maxTables {
			out.more = true
			break
		}
		switch {
		case !plain:
			out.excluded = append(out.excluded, ExcludedTable{Table: printable(table), Owner: unsupportedName})
		case !mine:
			out.excluded = append(out.excluded, ExcludedTable{Table: table, Owner: printable(owner)})
		default:
			out.tables = append(out.tables, ListedTable{Table: table, CanWrite: keyed})
		}
	}
	return out, rows.Err()
}

// printable replaces what a person cannot read safely in a name from the
// catalog.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) || bidiControl(r) {
			return '?'
		}
		return r
	}, s)
}

// bidiControl is a Unicode bidirectional control, which can reorder what a
// person reads.
func bidiControl(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	}
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// answersKey is the answers as the challenge binds them.
func answersKey(answers []Answer) string {
	parts := make([]string, len(answers))
	for i, a := range answers {
		parts[i] = a.Table + ":" + a.Choice
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// allRows answers every question ALL_ROWS, the page's answer.
func allRows(blind []guard.BlindTable) []Answer {
	out := make([]Answer, len(blind))
	for i, b := range blind {
		out[i] = Answer{Table: b.Table, Choice: ChoiceAllRows}
	}
	return out
}

// checkSchemas applies the rules of the request's schemas for a real
// install: 1 to 5 plain lowercase names, each once, none of the system
// schemas. Absent means public.
func checkSchemas(in []string) ([]string, error) {
	if in == nil {
		return []string{"public"}, nil
	}
	bad := refuse(CodeAnswersInvalid, "The schemas to list are not valid: give 1 to 5 plain lowercase schema names, each once, and none of the system schemas.")
	if len(in) == 0 || len(in) > maxSchemas {
		return nil, bad
	}
	seen := map[string]bool{}
	for _, s := range in {
		if !plainSchema.MatchString(s) || strings.HasPrefix(s, "pg_") || s == "information_schema" || s == "basalt_meta" || seen[s] {
			return nil, bad
		}
		seen[s] = true
	}
	return slices.Clone(in), nil
}

// checkPicks applies the shape rules of the picked tables: at most 500,
// each a plain lowercase schema.table inside the schemas, once, with an
// access of WRITE or READ. Whether a table exists is read in the
// transaction (TABLES_CHANGED).
func checkPicks(picks []TablePick, schemas []string) ([]TablePick, error) {
	bad := refuse(CodeAnswersInvalid, "A picked table is not a table of the listed schemas, is picked twice, has no valid access, or there are too many; check the setup again.")
	if len(picks) > maxTables {
		return nil, bad
	}
	seen := map[string]bool{}
	for _, p := range picks {
		schema, _, _ := strings.Cut(p.Table, ".")
		if !plainTable.MatchString(p.Table) || !slices.Contains(schemas, schema) || seen[p.Table] ||
			(p.Access != AccessWrite && p.Access != AccessRead) {
			return nil, bad
		}
		seen[p.Table] = true
	}
	out := slices.Clone(picks)
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out, nil
}

// picksKey is the picks as the challenge binds them.
func picksKey(picks []TablePick) string {
	parts := make([]string, len(picks))
	for i, p := range picks {
		parts[i] = p.Table + ":" + p.Access
	}
	return strings.Join(parts, ",")
}

// access splits the picks into the agent's write and read tables, refusing
// TABLES_CHANGED when a pick is not a table the listing holds, or asks for
// write on a table that cannot be written.
func (l listing) access(picks []TablePick) (write, read []string, err error) {
	byName := make(map[string]ListedTable, len(l.tables))
	for _, t := range l.tables {
		byName[t.Table] = t
	}
	for _, p := range picks {
		t, ok := byName[p.Table]
		switch {
		case !ok, p.Access == AccessWrite && !t.CanWrite:
			return nil, nil, refuse(CodeTablesChanged, "The tables changed since they were listed (a table was dropped, renamed, given to another owner or has no primary key), so nothing changed. Check the setup again.")
		case p.Access == AccessWrite:
			write = append(write, p.Table)
		default:
			read = append(read, p.Table)
		}
	}
	return write, read, nil
}

// questions are the row-level security questions of the blind tables.
func questions(blind []guard.BlindTable, agent string) []Question {
	out := make([]Question, 0, len(blind))
	for _, b := range blind {
		out = append(out, Question{Kind: "ROW_LEVEL_SECURITY", Table: b.Table, Text: setuprun.RLSQuestion(b, agent), Choices: []string{ChoiceAllRows, ChoiceNone}})
	}
	return out
}

// policies are the blind tables the person let the agent see every row of.
// One answer per question, no other: ANSWERS_INVALID otherwise.
func policies(blind []guard.BlindTable, answers []Answer) ([]guard.BlindTable, error) {
	bad := refuse(CodeAnswersInvalid, "The answers do not match the questions this setup asks: answer each question once. Check the setup again.")
	if len(answers) != len(blind) {
		return nil, bad
	}
	choice := map[string]string{}
	for _, a := range answers {
		_, dup := choice[a.Table]
		if dup || (a.Choice != ChoiceAllRows && a.Choice != ChoiceNone) || !slices.ContainsFunc(blind, func(b guard.BlindTable) bool { return b.Table == a.Table }) {
			return nil, bad
		}
		choice[a.Table] = a.Choice
	}
	// In the order of the questions, not of the answers.
	var out []guard.BlindTable
	for _, b := range blind {
		if choice[b.Table] == ChoiceAllRows {
			out = append(out, b)
		}
	}
	return out, nil
}

// realSummary is the lines of a real install's check.
func realSummary(j job, database string, write, read []string, passkeyNeeded, keep bool) []string {
	lines := []string{fmt.Sprintf("This sets up Basalt in the database %s.", database)}
	if keep {
		lines = append(lines, fmt.Sprintf("The agent %s (role %s) is already in the database, and this engine holds its password: this finishes its setup, which stopped before the engine wrote its config. Its password stays.", j.req.Agent, j.role))
	} else {
		lines = append(lines, fmt.Sprintf("It creates the agent %s (role %s), which runs as the OS user %s. Its password is made by this engine and kept on this computer only.", j.req.Agent, j.role, j.req.OSUser))
	}
	if len(write) > 0 {
		lines = append(lines, "The agent can read and change "+strings.Join(write, ", ")+".")
	}
	if len(read) > 0 {
		lines = append(lines, "The agent can only read "+strings.Join(read, ", ")+".")
	}
	lines = append(lines, "It can see no other table. Every write it makes is recorded, and a large one waits for your passkey.")
	if passkeyNeeded {
		lines = append(lines, "The database has no passkey for this computer yet: you create one now, and it approves the agent's held writes and reverts.")
	}
	return lines
}
