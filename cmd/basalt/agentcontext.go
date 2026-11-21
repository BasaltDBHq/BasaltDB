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

// agentFacing is true when what basalt prints is read by an agent rather
// than a person at a terminal: an agent marker is set, or stdin is not a
// terminal. Help then shows only the agent-led setup.
func (c *cliIO) agentFacing() bool {
	return c.agentMarker() != "" || !c.interactive
}

// What an agent does instead of a command that needs the admin credential.
const (
	hintAgentInit = "To set up an agent, run basalt init --remote --agent NAME --write schema.table,... " +
		"--database-url 'postgres://user@host:port/database' (the connection string WITHOUT the password) " +
		"and give the person the setup code it prints: they run basalt init --setup-code on their own computer."
	hintAgentSetupCode = "Give the person this command instead of running it: they run it in a terminal of their own, which no agent reads."
	hintAgentPerson    = "Give the person this command instead of running it: they run it in a terminal of their own, which no agent reads. " +
		"To set up or upgrade an agent, run basalt init --remote and give the person the setup code it prints."
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

// pipedAdminInitAllowed lets init without --remote take the admin
// connection string with stdin not a terminal. It is false in the binary;
// only the test binary sets it (its tests stand in for a person at a
// terminal), and a test sets strictInit to check the refusal.
var pipedAdminInitAllowed = false

// agentInitError refuses init without --remote whenever an agent may be
// the one running it: an agent marker is set, or stdin is not a terminal (a
// person types the admin connection string at a terminal; an MCP client
// that sets no marker still runs commands with no terminal). It refuses
// before BASALT_ADMIN_DATABASE_URL or stdin is read. Steps hand the agent
// basalt init --agent NAME (CONTRACT.md, Next steps); until the local setup
// page exists, that run ends here with this message, never with admin
// access.
func (c *cliIO) agentInitError() error {
	if err := c.agentContextError("basalt init without --remote", hintAgentInit); err != nil {
		return err
	}
	if c.interactive || (pipedAdminInitAllowed && !c.strictInit) {
		return nil
	}
	msg := "basalt init without --remote needs the database admin connection string, typed by a person at a terminal, " +
		"and stdin is not a terminal, so basalt does not read one. An agent never asks for, accepts or types the admin " +
		"connection string or password.\n" + hintAgentInit
	if c.getenv(envAdminURL) != "" {
		msg += "\n" + adminEnvLeaked
	}
	return fmt.Errorf("%s", msg)
}

// adminEnvLeaked is said when BASALT_ADMIN_DATABASE_URL is set where an
// agent runs: basalt does not use it, and the password it holds is exposed.
const adminEnvLeaked = envAdminURL + " is set where an agent can read it; basalt did not use it. " +
	"Remove it from this environment and ask the person to change that database password now."

// agentInitUsage is basalt init's help when an agent reads it: only the
// agent-led setup, never init with the admin credential, which an agent
// would have to ask the person for.
const agentInitUsage = `usage: basalt init --remote --agent NAME [--write schema.table,...] [--read schema.table,...] --database-url URL [flags]
         makes a setup code on this machine with no admin credential; URL is the
         connection string WITHOUT the password (see basalt init --remote -h)
       basalt init --setup-code CODE
         the person runs this on their own computer, in a terminal no agent reads

An agent never asks for, accepts or types the database admin connection string
or password. If the person pastes one, tell them to change that password now.
Give the person the setup code, its fingerprint and the basalt init --setup-code
command, then end your turn.

` + manyAgentsHelp + "\n"

// helpAsked is true when args ask for help, which basalt prints whoever
// runs it.
func helpAsked(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		switch a {
		case "-h", "-help", "--h", "--help":
			return true
		}
	}
	return false
}

// remoteAdminEnvSet is basalt init --remote's warning when
// BASALT_ADMIN_DATABASE_URL is set: it never uses it, and an agent on this
// machine may read it.
const remoteAdminEnvSet = envAdminURL + " is set here; basalt init --remote never uses it. " +
	"If an agent can read this environment, remove it and ask the person to change that database password now."

// errAgentNotInConfig: the config has no such agent. Whoever reads it may be
// an agent, so it names the agent-led setup only.
func errAgentNotInConfig(agent, configPath string) error {
	return fmt.Errorf("agent %q is not in %s; set it up with basalt init --remote --agent %s and give the person the setup code it prints", agent, configPath, agent)
}
