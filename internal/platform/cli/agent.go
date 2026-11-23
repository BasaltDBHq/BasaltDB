package cli

import (
	"fmt"
)

// EnvAgentContext is Basalt's own agent marker: set it to any non-empty
// value in the environment a bot's shell commands run in, so basalt treats
// every command there as run by an agent (CONTRACT.md, Agents and the admin
// credential).
const EnvAgentContext = "BASALT_AGENT_CONTEXT"

// AgentMarkers are the environment variables that say a command runs under
// an agent: Basalt's own marker first, then the ones known coding agents set
// in the shell they run commands in. A person's own terminal sets none of
// them. An agent can unset them, so they stop mistakes, not a determined
// agent: the boundary is basalt init --remote and separate OS users.
var AgentMarkers = []string{
	EnvAgentContext,
	"CLAUDECODE",                     // Claude Code
	"CODEX_SANDBOX",                  // Codex CLI
	"CODEX_SANDBOX_NETWORK_DISABLED", // Codex CLI
	"GEMINI_CLI",                     // Gemini CLI
	"CURSOR_AGENT",                   // Cursor's agent
	"OPENCODE",                       // OpenCode
}

// ErrAgentNotInConfig: the config has no such agent. Whoever reads it may be
// an agent, so it names the agent-led setup only.
func ErrAgentNotInConfig(agent, configPath string) error {
	return fmt.Errorf("agent %q is not in %s; set it up with basalt init --agent %s on the person's own computer, or basalt init --remote --agent %s on one the person cannot reach, and show the person the link it prints", agent, configPath, agent, agent)
}
