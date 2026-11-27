package guardmodel

import (
	"errors"
	"time"
)

const (
	// DefaultRoleStatementTimeout is the statement_timeout a setup sets on
	// the agent's role (ALTER ROLE ... SET), the limit on any connection
	// made with the role's credential. It is not the limit the engine puts
	// on the agent's own statements: the engine sets
	// action.DefaultStatementTimeout (5s, or limits.statementTimeoutMs) on every
	// transaction it runs, which wins over this role default.
	DefaultRoleStatementTimeout = 30 * time.Second
)

// UnpickedGrantsDetail is what the detail of the guard's BS008 refusal of
// an Exact agent spec says after the role's name, followed by the tables
// and sequences: the role still holds a privilege the setup grants on one
// that is not picked, and this admin could not revoke it. It holds no quote and no
// percent sign: it is written into the SQL as is. It is the Postgres guard's
// detail, here because the setup page (an inbound adapter, Postgres-only)
// reads it and may not import the guard adapter.
const UnpickedGrantsDetail = "still has access to tables or sequences that were not picked, and this admin cannot revoke it: "

// ErrInvalidAgent is returned for an agent spec that cannot be installed.
var ErrInvalidAgent = errors.New("invalid agent")

// AgentSpec is one agent role and the tables it may use. Tables are
// "schema.table" or "table" (schema public).
type AgentSpec struct {
	Name string
	// Password is the hex password to set (NewPassword). Postgres gets only
	// its SCRAM-SHA-256 verifier, never the password. Empty keeps the
	// password of a role that exists (AE-12); see AgentRoleExists.
	Password string
	// Verifier is the password as a SCRAM-SHA-256 verifier (a setup code,
	// checked by CheckVerifier), set in place of Password, which stays
	// empty. The person reads it in the SQL. It is sensitive: with one
	// observed SCRAM exchange of the role it lets its holder log in.
	Verifier string
	// CreateOnly creates the role with a plain CREATE ROLE, which Postgres
	// refuses when the role exists (an INSTALL setup code). Without it a
	// Verifier is set on the existing role with ALTER ROLE, which Postgres
	// refuses when the role does not exist (an AGENT setup code). Needs
	// Password or Verifier.
	CreateOnly bool
	// Change is an AGENT setup code: the role must already be a member of
	// the agents group (a setup code never pulls another role in), and its
	// table privileges are replaced by Read and Write, so tables no longer
	// listed lose theirs (CONTRACT.md, The setup code, kinds).
	Change bool
	// KeepGrants, with Change, keeps the role's table privileges: an AGENT
	// setup code that names no tables. The role must still be an agent of
	// the group; nothing is revoked and Read and Write are empty.
	KeepGrants bool
	// Exact is a local install that finishes with a role that already
	// exists (an earlier run was interrupted after its commit): before the
	// grants, the role loses the privileges the setup grants (SELECT,
	// INSERT, UPDATE and DELETE on a table, USAGE and SELECT on its serial
	// sequence) on every table outside Read and Write, so it ends with
	// exactly them. Grants the setup never makes are left as they are. A
	// setup grant on an unpicked table or sequence that this admin cannot
	// revoke (another role made it, and this admin cannot act for that role)
	// is refused (BS008, UnpickedGrantsDetail).
	Exact            bool
	Read             []string
	Write            []string
	StatementTimeout time.Duration
}
