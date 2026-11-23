package guardmodel

import (
	"errors"
	"fmt"
	"regexp"
)

// DefaultPrefix names the roles of a default install: basalt_guard,
// basalt_agents and basalt_agent_<name>.
const DefaultPrefix = "basalt"

const (
	// maxIdentLen is Postgres' identifier limit, NAMEDATALEN − 1.
	maxIdentLen = 63
	// maxPrefixLen leaves room for "_agent_" and an agent name.
	maxPrefixLen = 20
	// agentInfix joins the prefix and the agent name in an agent role.
	agentInfix = "_agent_"
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

// AgentPrefix is what every agent role's name starts with.
func (n Names) AgentPrefix() string { return n.Prefix + agentInfix }

// Agent is the LOGIN role of one agent.
func (n Names) Agent(name string) (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}
	role := n.AgentPrefix() + name
	if !identPattern.MatchString(name) || len(role) > maxIdentLen {
		return "", fmt.Errorf("%w: agent %q must match %s and the role %q fit in %d bytes",
			ErrInvalidName, name, identPattern, role, maxIdentLen)
	}
	return role, nil
}

// ValidAgentName reports whether name makes a valid agent role under the
// default prefix. The engine config and the CLI check names with it.
func ValidAgentName(name string) bool {
	_, err := Names{Prefix: DefaultPrefix}.Agent(name)
	return err == nil
}
