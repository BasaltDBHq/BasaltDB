// Package guard owns everything BasaltDB installs in the person's Postgres
// (the basalt_meta schema, its roles, triggers and ledger) and the calls
// the engine makes inside an agent's transactions. Agents write only
// through it: every write is recorded in the ledger, held for approval
// when the policy says so, and can be reverted. CONTRACT.md, basalt_meta,
// fixes the objects and their versions.
package guard

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultPrefix names the roles of a default install: basalt_guard,
// basalt_agents and basalt_agent_<name>.
const DefaultPrefix = "basalt"

const (
	// maxIdentLen is Postgres' identifier limit, NAMEDATALEN − 1.
	maxIdentLen = 63
	// maxPrefixLen leaves room for "_agent_" and an agent name.
	maxPrefixLen = 20
	agentInfix   = "_agent_"
)

// identPattern is the only shape a role-name part may take. Lowercase and
// unquoted, so a name is the same as an identifier and inside a literal.
var identPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ErrInvalidName is returned for a prefix or agent name that does not
// match identPattern or is too long.
var ErrInvalidName = errors.New("invalid name")

// Names builds the role names of one install. Roles are cluster objects,
// so two databases in one cluster need different prefixes.
type Names struct {
	Prefix string
}

// Validate checks the prefix.
func (n Names) Validate() error {
	if len(n.Prefix) > maxPrefixLen || !identPattern.MatchString(n.Prefix) {
		return fmt.Errorf("%w: prefix %q must match %s and be at most %d bytes",
			ErrInvalidName, n.Prefix, identPattern, maxPrefixLen)
	}
	return nil
}

// Guard is the NOLOGIN role that owns basalt_meta.
func (n Names) Guard() string { return n.Prefix + "_guard" }

// Agents is the NOLOGIN group every agent role belongs to.
func (n Names) Agents() string { return n.Prefix + "_agents" }

// Agent is the LOGIN role of one agent.
func (n Names) Agent(name string) (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}
	role := n.Prefix + agentInfix + name
	if !identPattern.MatchString(name) || len(role) > maxIdentLen {
		return "", fmt.Errorf("%w: agent %q must match %s and the role %q fit in %d bytes",
			ErrInvalidName, name, identPattern, role, maxIdentLen)
	}
	return role, nil
}

// render substitutes the validated role names into install SQL.
func (n Names) render(sql string) string {
	return strings.NewReplacer("{{guard}}", n.Guard(), "{{agents}}", n.Agents()).Replace(sql)
}

// ValidAgentName reports whether name makes a valid agent role under the
// default prefix. The engine config and the CLI check names with it.
func ValidAgentName(name string) bool {
	_, err := Names{Prefix: DefaultPrefix}.Agent(name)
	return err == nil
}
