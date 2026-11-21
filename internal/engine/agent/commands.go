package agent

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// Commands builds the commands a step names for one agent. A person never
// runs a basalt command (CONTRACT.md, Next steps): a person's step is a link
// to a page, and the one basalt command a step names is the agent's own
// `basalt init`, which prints that link. What is left is the engine's start
// and restart on the engine's machine.
type Commands struct {
	agent      string
	configPath string
	goos       string
	foreground bool
	// agentOperated: engine.json operatedBy is AGENT, so machine steps are
	// the agent's and setup goes through the connect page.
	agentOperated bool
}

// cmdBasalt is the CLI every command runs.
const cmdBasalt = "basalt"

// NewCommands returns the commands for agent. configPath is the absolute
// path the engine was started with ("" when the default); goos picks the
// default path and the service manager (runtime.GOOS when empty).
func NewCommands(agent, configPath, goos string) (Commands, error) {
	if !config.ValidAgentName(agent) {
		return Commands{}, fmt.Errorf("%q is not a valid agent name", agent)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if configPath != "" && !filepath.IsAbs(configPath) {
		return Commands{}, fmt.Errorf("config path %q must be absolute", configPath)
	}
	return Commands{agent: agent, goos: goos, configPath: configPath}, nil
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

// configFlag is "--config PATH", or "" when the engine runs from the default
// config. Only the plugin commands, which the plugin epic replaces, name it.
func (c Commands) configFlag() string {
	if c.configPath == "" || c.configPath == config.DefaultPath(c.goos) {
		return ""
	}
	return "--config " + shellQuote(c.configPath)
}

// EngineStart starts the engine: the foreground command, or the service
// manager's start for the installed service.
func (c Commands) EngineStart() string {
	if c.foreground {
		return c.foregroundEngine()
	}
	return service.StartCommand(c.goos)
}

// EngineRestart restarts the engine: the foreground command again, or the
// service manager's restart.
func (c Commands) EngineRestart() string {
	if c.foreground {
		return c.foregroundEngine()
	}
	return "sudo " + strings.Join(service.RestartArgs(c.goos), " ")
}

func (c Commands) foregroundEngine() string {
	path := c.configPath
	if path == "" {
		path = config.DefaultPath(c.goos)
	}
	return "basalt engine --config " + shellQuote(path)
}

// shellQuote quotes s for a POSIX shell when it needs it. A leading = is
// quoted too: zsh expands =cmd to a path.
func shellQuote(s string) string {
	if s != "" && !strings.HasPrefix(s, "=") &&
		strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
