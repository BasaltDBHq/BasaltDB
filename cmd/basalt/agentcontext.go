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
	hintAgentInit = "To set up an agent, run basalt init --remote --agent NAME and show the person the link it prints: " +
		"they finish the setup on that page."
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
// connection string with stdin not a terminal, or from
// BASALT_ADMIN_DATABASE_URL. It is false in the binary; only the test
// binary sets it (its tests stand in for a person at a terminal), and a
// test sets strictInit to check the refusals.
var pipedAdminInitAllowed = false

// agentInitError refuses init without --remote whenever an agent may be
// the one running it: an agent marker is set, or stdin is not a terminal (a
// person types the admin connection string at a terminal; an MCP client
// that sets no marker still runs commands with no terminal). It refuses
// before BASALT_ADMIN_DATABASE_URL or stdin is read, and refuses a set
// BASALT_ADMIN_DATABASE_URL too: init never uses it (removed, CONTRACT.md,
// Environment variables). Steps hand the agent
// basalt init --agent NAME (CONTRACT.md, Next steps); until the local setup
// page exists, that run ends here with this message, never with admin
// access.
func (c *cliIO) agentInitError() error {
	if err := c.agentContextError("basalt init without --remote", hintAgentInit); err != nil {
		return err
	}
	if !c.interactive && c.strict() {
		return c.noTerminalInitError()
	}
	if c.getenv(envAdminURL) != "" && c.strict() {
		// Removed (CONTRACT.md, Environment variables): init never uses it.
		return fmt.Errorf("%s", adminEnvRefused)
	}
	return nil
}

// strict is false only in the test binary, whose tests stand in for a
// person at init's prompt (pipedAdminInitAllowed), unless a test sets
// strictInit.
func (c *cliIO) strict() bool { return !pipedAdminInitAllowed || c.strictInit }

// initAdminURL is plain init's admin connection string, typed at its
// prompt. Only the test binary takes it from BASALT_ADMIN_DATABASE_URL
// (strict), standing in for the person typing it.
func (c *cliIO) initAdminURL() (string, error) {
	if v := c.getenv(envAdminURL); v != "" && !c.strict() {
		return v, nil
	}
	return c.promptAdminURL()
}

// adminEnvRefused is init's refusal when BASALT_ADMIN_DATABASE_URL is set:
// the variable is removed, basalt does not use its value, and whoever can
// read this environment holds that password.
const adminEnvRefused = "basalt init does not read " + envAdminURL + ": the admin connection string is typed only at its prompt, " +
	"so basalt did not use it. It is set in this environment, where other programs and agents can read it: remove it and " +
	"change that database password now, then run basalt init again."

// noTerminalInitError is agentInitError's refusal when stdin is not a
// terminal.
func (c *cliIO) noTerminalInitError() error {
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
const agentInitUsage = `usage: basalt init --remote [--agent NAME]
         sets up an agent on this machine with no admin credential and prints
         the connect link the person opens

An agent never asks for, accepts or types the database admin connection string
or password. If the person pastes one, tell them to change that password now.
Show the person the link and its fingerprint, then end your turn.

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
