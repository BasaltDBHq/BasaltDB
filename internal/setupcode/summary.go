package setupcode

import (
	"fmt"
	"strings"
)

// Row limits of the default policy the summary names (guard schema: up to
// 10 rows allowed, 11 to 50 held for a passkey, more refused).
const (
	summaryAutoRows = 10
	summaryHoldRows = 50
)

// AgentConnectionLimit is the CONNECTION LIMIT init gives every agent
// role; guard.AgentConnectionLimit is the same value and gives the budget.
// It is defined here because guard imports this package.
const AgentConnectionLimit = 8

// publicSchema is the schema whose tables the summary does not flag.
const publicSchema = "public"

// supabaseSchemas are Supabase's own schemas: a table there is flagged more
// strongly when the target is a Supabase project.
var supabaseSchemas = map[string]bool{"auth": true, "storage": true}

// SummaryState is what the summary needs from the database, read with the
// admin connection string.
type SummaryState struct {
	// GuardVersion is the installed basalt_meta version (0 when none).
	GuardVersion int
	// TimeoutNow is the agent role's current statement_timeout as shown
	// after "now" ("15000 ms", "not set"), only when an AGENT code changes
	// it; empty otherwise.
	TimeoutNow string
	// TimeoutThisDatabase is the agent role's statement_timeout set for
	// this database only (ALTER ROLE ... IN DATABASE), which takes
	// precedence over the one the code sets, shown the same way; empty when
	// it has none there or it is the code's.
	TimeoutThisDatabase string
	// RunsAsInstall is a connect-only recovery AGENT code whose role does
	// not exist: the connect service runs it as an INSTALL.
	RunsAsInstall bool
	// Tables are, with agent.allTables, the tables the agent may change,
	// read from the database; nil when not read (the summary then names the
	// schema). ReadOnly are those it may only read: no primary key.
	Tables   []string
	ReadOnly []string
	// Excluded are, with agent.allTables, the tables of the schema left out
	// because the admin role does not own them.
	Excluded []ExcludedTable
}

// ExcludedTable is a table of an agent.allTables schema that the setup
// leaves out, because the admin role does not own it.
type ExcludedTable struct {
	// Table is schema.table.
	Table string
	// Owner is the role that owns it.
	Owner string
}

// Summary is what the setup shows before the SQL, one line
// per item (CONTRACT.md, The setup checks, step 5): what the code
// does to the agent's role, in fixed words; the prefix and statement
// timeout; the fingerprint to compare with the agent's; what the agent
// gets, in words; and a flag per table outside public. A Payload that
// passed Decode is displayable: names and tables are plain identifiers.
func Summary(p Payload, s SummaryState) []string {
	name, role := p.agentWord(), p.Role()
	var out []string
	switch {
	case p.Kind == KindInstall || s.RunsAsInstall:
		out = append(out, fmt.Sprintf("This creates the agent %s (role %s). Its password comes from the code: only whoever made this code can log in as %s.",
			name, role, role))
	case p.Kind == KindAgent && p.Agent.Verifier != "":
		out = append(out, fmt.Sprintf("This replaces the password of the existing agent %s (role %s): only whoever made this code can then log in as %s. "+
			"Run it only if %s itself gave you this code.", name, role, role, name))
	case p.Kind == KindAgent:
		out = append(out, fmt.Sprintf("This changes the tables of the existing agent %s (role %s); its password stays.", name, role))
	default:
		out = append(out, UpgradeLine(s.GuardVersion, p.Guard.To))
	}
	if p.Agent == nil {
		out = append(out, fmt.Sprintf("Prefix %s.", p.Prefix))
	} else {
		line := fmt.Sprintf("Prefix %s, statement timeout %d ms", p.Prefix, p.Agent.StatementTimeoutMs)
		if p.Kind == KindAgent && !s.RunsAsInstall {
			line += timeoutNote(s)
		}
		out = append(out, fmt.Sprintf("%s, at most %d connections.", line, AgentConnectionLimit))
	}
	out = append(out, fmt.Sprintf("Setup fingerprint: %s. Check that %s shows the same fingerprint.", p.Fingerprint(), name))
	if p.Agent == nil {
		return out
	}
	if p.Agent.AllTables != nil {
		return append(out, allTablesLines(p.Agent, s)...)
	}
	out = append(out, grantsSentence(p.Agent))
	for _, t := range append(append([]string{}, p.Agent.Write...), p.Agent.Read...) {
		schema, _, _ := strings.Cut(t, ".")
		switch {
		case p.Target != nil && p.Target.SupabaseRef != "" && supabaseSchemas[schema]:
			out = append(out, fmt.Sprintf("Warning: %s is in Supabase's own %s schema. An agent there can reach your users' accounts or files: run this only if you are sure.", t, schema))
		case schema != publicSchema:
			out = append(out, fmt.Sprintf("Note: %s is not in schema %s: check you meant this table.", t, publicSchema))
		}
	}
	return out
}

// timeoutNote is " (now <m> ms)" when the role's current statement_timeout
// differs from the code's, plus the one set for this database only, which
// wins over it; "" when neither differs.
func timeoutNote(s SummaryState) string {
	var parts []string
	if s.TimeoutNow != "" {
		parts = append(parts, "now "+s.TimeoutNow)
	}
	if s.TimeoutThisDatabase != "" {
		parts = append(parts, s.TimeoutThisDatabase+" set for this database only, which takes precedence")
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// allTablesLines say what an agent.allTables code grants: the tables by
// name once read from the database (s.Tables), else the schema, then each
// table left out. The schema is public, so no table is flagged.
func allTablesLines(a *Agent, s SummaryState) []string {
	if s.Tables == nil {
		return []string{fmt.Sprintf("%s will be able to read and change rows in every table in schema %s that the admin role owns when the setup runs, %s. "+
			"It cannot change your tables' structure.", a.Name, strings.Join(a.AllTables.Schemas, ", "), rowLimits())}
	}
	out := []string{grantsSentence(&Agent{Name: a.Name, Write: s.Tables, Read: s.ReadOnly})}
	for _, t := range s.ReadOnly {
		out = append(out, fmt.Sprintf("%s has no primary key, so %s can read it but not change its rows.", t, a.Name))
	}
	for _, e := range s.Excluded {
		out = append(out, fmt.Sprintf("%s is not included: owned by %s.", e.Table, e.Owner))
	}
	return out
}

// rowLimits are the default policy's row limits in words.
func rowLimits() string {
	return fmt.Sprintf("up to %d rows at a time without asking you, %d to %d with your passkey, never more",
		summaryAutoRows, summaryAutoRows+1, summaryHoldRows)
}

// grantsSentence says in words what the agent can do with its tables.
func grantsSentence(a *Agent) string {
	limits := rowLimits()
	const structure = "It cannot change your tables' structure."
	switch {
	case len(a.Write) == 0:
		return fmt.Sprintf("%s will be able to read %s. It cannot change their rows. %s", a.Name, listWords(a.Read), structure)
	case len(a.Read) == 0:
		return fmt.Sprintf("%s will be able to read and change rows in %s, %s. %s", a.Name, listWords(a.Write), limits, structure)
	default:
		return fmt.Sprintf("%s will be able to read %s and change rows in %s, %s. %s",
			a.Name, listWords(a.Read), listWords(a.Write), limits, structure)
	}
}

// listWords joins items as "a, b and c".
func listWords(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// UpgradeLine is the fixed sentence for a guard upgrade from version from to
// version to: an UPGRADE code's summary.
func UpgradeLine(from, to int) string {
	return fmt.Sprintf("This upgrades Basalt's guard from version %d to %d; no agent changes.", from, to)
}
