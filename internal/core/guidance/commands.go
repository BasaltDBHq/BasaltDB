package guidance

import (
	"strings"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// Commands builds the commands a step names for one agent. A person never
// runs a basalt command (CONTRACT.md, Next steps): a person's step is a link
// to a page, and the one basalt command a step names is the agent's own
// `basalt init`, which prints that link. What is left is the engine's start
// and restart on the engine's machine.
type Commands struct {
	agent      string
	configPath string
	// defaultConfigPath is where the engine reads its config when it was
	// started with none (configPath is empty).
	defaultConfigPath string
	goos              string
	foreground        bool
	// agentOperated: engine.json operatedBy is AGENT, so machine steps are
	// the agent's and setup goes through the connect page.
	agentOperated bool
	// updateLink is the setup page's UPDATE link for this agent, when the
	// engine serves the setup page (UpdateLink).
	updateLink string
	// removed reports a person-operated engine whose engine.json a setup
	// page REMOVE deleted (Removed); nil when it cannot happen.
	removed func() bool
	// manager is the host's service manager.
	manager ServiceManager
}

// ServiceManager is the host's service manager: the command that starts the
// engine service and the command line that restarts it, for goos.
type ServiceManager struct {
	StartCommand func(goos string) string
	RestartArgs  func(goos string) []string
}

// cmdBasalt is the CLI every command runs.
const cmdBasalt = "basalt"

// NewCommands returns the commands for agent. configPath is the absolute
// path the engine was started with ("" when the default), and
// defaultConfigPath the path the engine uses then; goos picks the service
// manager's commands. The caller has checked agent and configPath.
func NewCommands(agent, configPath, defaultConfigPath, goos string, manager ServiceManager) Commands {
	return Commands{agent: agent, goos: goos, configPath: configPath, defaultConfigPath: defaultConfigPath, manager: manager}
}

// Foreground returns c for an engine that runs in the foreground as the
// person's own command, not as a service: its start and restart are
// `basalt engine --config PATH`.
func (c Commands) Foreground() Commands {
	c.foreground = true
	return c
}

// OperatedBy returns c for an engine whose engine.json operatedBy is
// operatedBy: AGENT makes machine steps the agent's (CONTRACT.md, Next
// steps, Who runs machine steps); anything else, PERSON included, keeps
// them the person's.
func (c Commands) OperatedBy(operatedBy string) Commands {
	c.agentOperated = operatedBy == mcpcontract.OperatedByAgent
	return c
}

// UpdateLink returns c with the setup page's UPDATE link for this agent
// (CONTRACT.md, The local setup page): a guard update's steps hand it to
// the person instead of running basalt init. Empty keeps basalt init.
func (c Commands) UpdateLink(link string) Commands {
	c.updateLink = link
	return c
}

// Removed returns c with removed, which reports whether the setup page's
// REMOVE deleted this engine's engine.json: the agent's fix steps then
// run basalt init, whose page asks the person to set BasaltDB up again or
// finish the removal.
func (c Commands) Removed(removed func() bool) Commands {
	c.removed = removed
	return c
}

// EngineRemoved reports whether Removed's func says the engine is removed.
func (c Commands) EngineRemoved() bool { return c.removed != nil && c.removed() }

// UpdateLinkURL is the setup page's UPDATE link UpdateLink set, or "".
func (c Commands) UpdateLinkURL() string { return c.updateLink }

// AgentName is the agent the commands are for.
func (c Commands) AgentName() string { return c.agent }

// AgentOperated reports whether the engine's operatedBy is AGENT.
func (c Commands) AgentOperated() bool { return c.agentOperated }

// Init is the agent's `basalt init` for this agent: it starts the one setup
// flow (setup, guard update, repair, passkeys, tables) and prints the one
// link the person opens (CONTRACT.md, basalt init). It names --agent, so it
// is right however many agents the engine serves, and --remote on an
// agent-operated engine, whose setup runs on the connect page. It never
// carries saved flags, --config or a secret.
func (c Commands) Init() string {
	parts := []string{cmdBasalt, "init", "--agent", c.agent}
	if c.agentOperated {
		parts = append(parts, "--remote")
	}
	return strings.Join(parts, " ")
}

// EngineStart starts the engine: the foreground command, or the service
// manager's start for the installed service.
func (c Commands) EngineStart() string {
	if c.foreground {
		return c.foregroundEngine()
	}
	return c.manager.StartCommand(c.goos)
}

// EngineRestart restarts the engine: the foreground command again, or the
// service manager's restart.
func (c Commands) EngineRestart() string {
	if c.foreground {
		return c.foregroundEngine()
	}
	return "sudo " + strings.Join(c.manager.RestartArgs(c.goos), " ")
}

func (c Commands) foregroundEngine() string {
	path := c.configPath
	if path == "" {
		path = c.defaultConfigPath
	}
	return "basalt engine --config " + ShellQuote(path)
}

// ShellQuote quotes s for a POSIX shell when it needs it. A leading = is
// quoted too: zsh expands =cmd to a path.
func ShellQuote(s string) string {
	if s != "" && !strings.HasPrefix(s, "=") &&
		strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellJoin quotes each argument with ShellQuote and joins them for display.
func ShellJoin(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, ShellQuote(a))
	}
	return strings.Join(out, " ")
}
