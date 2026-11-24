package guardmodel

import (
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The data a setup plans and reads, shared by the guard's SQL functions and
// the setup service that calls them.

// InitOptions configures planning an install. Agent is optional: an empty
// Name installs or upgrades basalt_meta only.
type InitOptions struct {
	Names Names
	Agent AgentSpec
	// AgentPolicies are the agent's tables the person confirmed the agent
	// may see every row of (from AgentBlindTables). Each gets a policy
	// named after the agent role and a ledger row; nothing else does.
	AgentPolicies []BlindTable
	// UpTo stops the migrations at this version (a setup code's guard.to);
	// 0 applies every migration this build has.
	UpTo int
}

// Statement is one step of a Script. Shown is what the person sees when it
// differs from SQL (a password redacted).
type Statement struct {
	SQL   string
	Shown string
}

// Script is the ordered SQL an install, a repair or a removal runs, in one
// transaction.
type Script struct {
	Statements []Statement
	// Warnings are for the person, shown before the script runs; none
	// stops it.
	Warnings []string
}

// SQL renders the script for the person to read, secrets redacted.
func (s Script) SQL() string {
	parts := make([]string, 0, len(s.Statements))
	for _, st := range s.Statements {
		text := st.SQL
		if st.Shown != "" {
			text = st.Shown
		}
		parts = append(parts, strings.TrimSpace(text))
	}
	return strings.Join(parts, "\n\n") + "\n"
}

// BlindTable is one of an agent's tables where row-level security hides
// every row from the agent role.
type BlindTable struct {
	// Table is schema.table.
	Table string
	// Rows is how many rows the table holds, counted by the admin.
	Rows int64
	// Write is true for a --write table: its agent policy is FOR ALL.
	Write bool
}

// RegisteredPasskey is an active passkey as the admin connection sees it:
// its public data, never key material.
type RegisteredPasskey struct {
	ID         []byte
	Label      string
	RPID       string
	Origin     string
	UserHandle []byte
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// SchemaTables are the tables of a schema as an agent.allTables setup sees
// them, each in name order.
type SchemaTables struct {
	// Write are the tables the connected role owns that have a primary key:
	// the agent may change their rows.
	Write []string
	// ReadOnly are the tables the connected role owns without a primary
	// key: the guard cannot key an agent's writes there, so the agent may
	// only read them.
	ReadOnly []string
	// Excluded are the tables another role owns.
	Excluded []setupcode.ExcludedTable
}

// RecordedEngine is a row of basalt_meta.engines: an engine's public
// identity and whether it is revoked. Never key material beyond the public
// key.
type RecordedEngine struct {
	ID         string
	PublicKey  []byte
	RecordedAt time.Time
	RevokedAt  *time.Time
}

// RoleTimeouts is the statement_timeout a role has set, as Postgres stores
// it ("30000", "30s"); "" for one it has not set.
type RoleTimeouts struct {
	// AllDatabases is ALTER ROLE ... SET, what basalt sets.
	AllDatabases string
	// ThisDatabase is ALTER ROLE ... IN DATABASE <the connected one> SET,
	// which takes precedence over AllDatabases in that database.
	ThisDatabase string
}

// Uncovered is an agent-writable table or cascade target without the guard.
type Uncovered struct {
	Table string
	Why   string
}

// DemoPlan is what seeding the sample schema will run.
type DemoPlan struct {
	// SQL is what runs, in order; empty when the sample already exists.
	SQL []string
}

// Shown is the SQL the person reads before confirming.
func (p DemoPlan) Shown() string {
	var b strings.Builder
	for _, s := range p.SQL {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// Exists: both sample tables are there, and nothing is seeded.
func (p DemoPlan) Exists() bool { return len(p.SQL) == 0 }
