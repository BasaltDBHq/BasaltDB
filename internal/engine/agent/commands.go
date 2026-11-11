package agent

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Commands builds the commands the person runs, for one agent: complete and
// copy-pasteable, never carrying a credential value (AE-3). The engine's
// config path is named with --config only when it is not the default the
// CLI finds by itself on this platform.
type Commands struct {
	agent      string
	flags      string // --agent NAME [--config PATH]
	configFlag string // --config PATH, or empty at the default
	configPath string
	goos       string
	initArgs   []string
	foreground bool
}

const (
	flagAgent         = "agent"
	flagPasskeyOrigin = "passkey-origin"
)

// savedInitFlags are the init flags a saved plan may carry (CONTRACT.md,
// Planned: init saves its flags). --credential-file is a path, not a secret
// (AE-15, provisional). Anything else is refused.
var savedInitFlags = map[string]bool{
	flagAgent: true, "write": true, "read": true, "prefix": true, "statement-timeout": true,
	"socket-dir": true, "os-user": true, "engine-user": true, "credential-file": true,
	flagPasskeyOrigin: true, "agent-rls": true, "operated-by": true,
}

// NewCommands returns the commands for agent. configPath is the absolute
// path the engine was started with ("" when the default); goos picks the
// default path and the service manager (runtime.GOOS when empty); initArgs
// are the flags the agent's `basalt init` was run with, saved by init.
func NewCommands(agent, configPath, goos string, initArgs []string) (Commands, error) {
	if !config.ValidAgentName(agent) {
		return Commands{}, fmt.Errorf("%q is not a valid agent name", agent)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if configPath != "" && !filepath.IsAbs(configPath) {
		return Commands{}, fmt.Errorf("config path %q must be absolute", configPath)
	}
	if err := checkInitArgs(agent, initArgs); err != nil {
		return Commands{}, err
	}
	c := Commands{agent: agent, goos: goos, configPath: configPath, initArgs: append([]string(nil), initArgs...)}
	c.flags = "--agent " + agent
	if configPath != "" && configPath != config.DefaultPath(goos) {
		c.configFlag = "--config " + shellQuote(configPath)
		c.flags += " " + c.configFlag
	}
	return c, nil
}

// checkInitArgs allows only the flags init saves, in `-flag` or `--flag`
// form, with the value after `=` or as the next argument, and refuses
// anything that looks like a connection string.
func checkInitArgs(agent string, args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return fmt.Errorf("saved init argument %q is not a flag", a)
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !savedInitFlags[name] {
			return fmt.Errorf("saved init flag %q is not one init saves", a)
		}
		if !hasValue {
			i++
			if i >= len(args) {
				return fmt.Errorf("saved init flag %q has no value", a)
			}
			value = args[i]
		}
		if looksLikeConnectionString(name, value) {
			return fmt.Errorf("saved init argument %q looks like a connection string", value)
		}
		if name == flagAgent && value != agent {
			return fmt.Errorf("saved init arguments name agent %q, not %q", value, agent)
		}
	}
	return nil
}

// looksLikeConnectionString is a value with a URL scheme or a password
// keyword. The one URL init saves is --passkey-origin, an origin without
// user info.
func looksLikeConnectionString(flag, value string) bool {
	if strings.Contains(strings.ToLower(value), "password=") {
		return true
	}
	if !strings.Contains(value, "://") {
		return false
	}
	return flag != flagPasskeyOrigin || strings.Contains(value, "@")
}

// hasAgentFlag reports whether the saved init arguments name the agent.
func (c Commands) hasAgentFlag() bool {
	for _, a := range c.initArgs {
		if name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); name == flagAgent && strings.HasPrefix(a, "-") {
			return true
		}
	}
	return false
}

// Foreground returns c for an engine that runs in the foreground as the
// person's own command, not as a service: its start and restart are
// `basalt engine --config PATH`.
func (c Commands) Foreground() Commands {
	c.foreground = true
	return c
}

// Flags are "--agent NAME [--config PATH]", to put after a basalt verb.
func (c Commands) Flags() string { return c.flags }

// Approve opens a held write's approval page.
func (c Commands) Approve(id uuid.UUID) string {
	return c.verb("approve", "--open", id.String())
}

// Revert opens the revert page for scope.
func (c Commands) Revert(scope guard.RevertScope) string {
	return c.verb("revert", "--"+strings.ToLower(string(scope.Kind)), scope.ID.String(), "--open")
}

// RevertStatus shows a revert's progress.
func (c Commands) RevertStatus(id uuid.UUID) string {
	return c.verb("revert", "--status", id.String())
}

// PasskeyList lists the passkeys the database accepts.
func (c Commands) PasskeyList() string { return c.verb("passkey list") }

// Upgrade upgrades the guard in the person's database.
func (c Commands) Upgrade() string { return c.verb("upgrade") }

// Init runs init again with the agent's saved flags plus one change (for
// example "--add-passkey"). The saved flags already name the agent.
func (c Commands) Init(change string) string {
	parts := []string{"basalt", "init"}
	if !c.hasAgentFlag() {
		parts = append(parts, "--agent", c.agent)
	}
	if c.configFlag != "" {
		parts = append(parts, c.configFlag)
	}
	for _, a := range c.initArgs {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(append(parts, change), " ")
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

// verb is `basalt <verb> <flags> <args...>`; verb may be a verb and its
// subcommand ("passkey list").
func (c Commands) verb(verb string, args ...string) string {
	return strings.Join(append([]string{"basalt", verb, c.flags}, args...), " ")
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
