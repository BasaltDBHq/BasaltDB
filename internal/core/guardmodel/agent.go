package guardmodel

import (
	"errors"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

const (
	// DefaultStatementTimeout is the agent role's query time limit.
	DefaultStatementTimeout = 30 * time.Second
	// AgentConnectionLimit is the agent role's CONNECTION LIMIT: the
	// engine's pool (4), basalt status (1), the setup finisher (1), and 2
	// spare for sessions a crashed engine leaves open until TCP keepalive
	// closes them. Postgres enforces it at login, whatever the engine does.
	// The value lives in setupcode, whose summary states it (setupcode
	// cannot import guard).
	AgentConnectionLimit = setupcode.AgentConnectionLimit
)

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
	KeepGrants       bool
	Read             []string
	Write            []string
	StatementTimeout time.Duration
}
