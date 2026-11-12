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
}

// Summary is what basalt init --setup-code shows before the SQL, one line
// per item (CONTRACT.md, basalt init --setup-code, step 5): what the code
// does to the agent's role, in fixed words; the prefix and statement
// timeout; the fingerprint to compare with the agent's; what the agent
// gets, in words; and a flag per table outside public. A Payload that
// passed Decode is displayable: names and tables are plain identifiers.
func Summary(p Payload, s SummaryState) []string {
	name, role := p.agentWord(), p.Role()
	var out []string
	switch {
	case p.Kind == KindInstall:
		out = append(out, fmt.Sprintf("This creates the agent %s (role %s). Its password comes from the code: only whoever made this code can log in as %s.",
			name, role, role))
	case p.Kind == KindAgent && p.Agent.Verifier != "":
		out = append(out, fmt.Sprintf("This replaces the password of the existing agent %s (role %s): only whoever made this code can then log in as %s. "+
			"Run it only if %s itself gave you this code.", name, role, role, name))
	case p.Kind == KindAgent:
		out = append(out, fmt.Sprintf("This changes the tables of the existing agent %s (role %s); its password stays.", name, role))
	default:
		out = append(out, fmt.Sprintf("This upgrades Basalt's guard from version %d to %d; no agent changes.", s.GuardVersion, p.Guard.To))
	}
	if p.Agent == nil {
		out = append(out, fmt.Sprintf("Prefix %s.", p.Prefix))
	} else {
		line := fmt.Sprintf("Prefix %s, statement timeout %d ms", p.Prefix, p.Agent.StatementTimeoutMs)
		if p.Kind == KindAgent && s.TimeoutNow != "" {
			line += " (now " + s.TimeoutNow + ")"
		}
		out = append(out, line+".")
	}
	out = append(out, fmt.Sprintf("Setup fingerprint: %s. Check that %s shows the same fingerprint.", p.Fingerprint(), name))
	if p.Agent == nil {
		return out
	}
	out = append(out, grantsSentence(p.Agent))
	for _, t := range append(append([]string{}, p.Agent.Write...), p.Agent.Read...) {
		schema, _, _ := strings.Cut(t, ".")
		switch {
		case p.Target.SupabaseRef != "" && supabaseSchemas[schema]:
			out = append(out, fmt.Sprintf("Warning: %s is in Supabase's own %s schema. An agent there can reach your users' accounts or files: run this only if you are sure.", t, schema))
		case schema != publicSchema:
			out = append(out, fmt.Sprintf("Note: %s is not in schema %s: check you meant this table.", t, publicSchema))
		}
	}
	return out
}

// grantsSentence says in words what the agent can do with its tables.
func grantsSentence(a *Agent) string {
	limits := fmt.Sprintf("up to %d rows at a time without asking you, %d to %d with your passkey, never more",
		summaryAutoRows, summaryAutoRows+1, summaryHoldRows)
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
