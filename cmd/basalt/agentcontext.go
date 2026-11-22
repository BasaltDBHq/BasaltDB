package main

import (
	"fmt"
	"strings"
)

// envAgentContext is Basalt's own agent marker: set it to any non-empty
// value in the environment a bot's shell commands run in, so basalt treats
// every command there as run by an agent (CONTRACT.md, Agents and the admin
// credential).
const envAgentContext = "BASALT_AGENT_CONTEXT"

// agentMarkers are the environment variables that say a command runs under
// an agent: Basalt's own marker first, then the ones known coding agents set
// in the shell they run commands in. A person's own terminal sets none of
// them. An agent can unset them, so they stop mistakes, not a determined
// agent: the boundary is basalt init --remote and separate OS users.
var agentMarkers = []string{
	envAgentContext,
	"CLAUDECODE",                     // Claude Code
	"CODEX_SANDBOX",                  // Codex CLI
	"CODEX_SANDBOX_NETWORK_DISABLED", // Codex CLI
	"GEMINI_CLI",                     // Gemini CLI
	"CURSOR_AGENT",                   // Cursor's agent
	"OPENCODE",                       // OpenCode
}

// agentMarker is the first agent marker set in the environment, or "" when
// none is: then basalt runs as for a person.
func (c *cliIO) agentMarker() string {
	for _, k := range agentMarkers {
		if strings.TrimSpace(c.getenv(k)) != "" {
			return k
		}
	}
	return ""
}

// What an agent does instead of a command that needs the admin credential.
const (
	hintAgentPerson = "Give the person this command instead of running it: they run it in a terminal of their own, which no agent reads. " +
		"To set up or change an agent, run basalt init (basalt init --remote on a computer the person cannot reach) and show the person the link it prints."
)

// agentContextError refuses a command that needs the admin connection
// string when it runs under an agent: the credential is never read, from
// the environment or a prompt. When BASALT_ADMIN_DATABASE_URL is set the
// agent could read it, so the person is told to change that password; its
// value is never echoed.
func (c *cliIO) agentContextError(command, hint string) error {
	marker := c.agentMarker()
	if marker == "" {
		return nil
	}
	msg := fmt.Sprintf("%s needs the database admin connection string, and it is running under an agent (%s is set), "+
		"so basalt does not read one. An agent never asks for, accepts or types the admin connection string or password.\n%s",
		command, marker, hint)
	if c.getenv(envAdminURL) != "" {
		msg += "\n" + adminEnvLeaked
	}
	return fmt.Errorf("%s", msg)
}

// adminEnvLeaked is said when BASALT_ADMIN_DATABASE_URL is set where an
// agent runs: basalt does not use it, and the password it holds is exposed.
const adminEnvLeaked = envAdminURL + " is set where an agent can read it; basalt did not use it. " +
	"Remove it from this environment and ask the person to change that database password now."

// remoteAdminEnvSet is basalt init --remote's warning when
// BASALT_ADMIN_DATABASE_URL is set: it never uses it, and an agent on this
// machine may read it.
const remoteAdminEnvSet = envAdminURL + " is set here; basalt init --remote never uses it. " +
	"If an agent can read this environment, remove it and ask the person to change that database password now."

// errAgentNotInConfig: the config has no such agent. Whoever reads it may be
// an agent, so it names the agent-led setup only.
func errAgentNotInConfig(agent, configPath string) error {
	return fmt.Errorf("agent %q is not in %s; set it up with basalt init --agent %s on the person's own computer, or basalt init --remote --agent %s on one the person cannot reach, and show the person the link it prints", agent, configPath, agent, agent)
}
