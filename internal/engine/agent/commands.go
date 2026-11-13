package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
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
	// agentOperated: engine.json operatedBy is AGENT, so machine steps are
	// the agent's and admin steps run on the person's own computer.
	agentOperated bool
}

const (
	flagAgent         = "agent"
	flagWrite         = "write"
	flagRead          = "read"
	flagPasskeyOrigin = "passkey-origin"
	// cmdBasalt is the CLI every command runs.
	cmdBasalt = "basalt"
)

// savedInitFlags are the init flags a saved plan may carry (CONTRACT.md,
// Planned: init saves its flags). --credential-file is a path, not a secret
// (AE-15, provisional). Anything else is refused.
var savedInitFlags = map[string]bool{
	flagAgent: true, flagWrite: true, flagRead: true, "prefix": true, "statement-timeout": true,
	"socket-dir": true, "os-user": true, "engine-user": true, "credential-file": true,
	flagPasskeyOrigin: true, "agent-rls": true, "operated-by": true, flagDevLocalPages: true,
}

// flagDevLocalPages is init's development exception (CONTRACT.md, Page
// origins); InitPortal leaves it out.
const flagDevLocalPages = "dev-local-pages"

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

// Access lists the tables the agent can read and write and the ones it
// cannot read (CONTRACT.md, CLI, basalt access): the person's command, never
// the agent's, since it names tables describe only counts.
func (c Commands) Access() string { return c.verb("access") }

// Upgrade upgrades the guard in the person's database.
func (c Commands) Upgrade() string { return c.verb("upgrade") }

// Init runs init again with the agent's saved flags plus one change (for
// example "--add-passkey"). The saved flags already name the agent.
func (c Commands) Init(change string) string {
	parts := []string{cmdBasalt, "init"}
	if !c.hasAgentFlag() {
		parts = append(parts, "--agent", c.agent)
	}
	if c.configFlag != "" {
		parts = append(parts, c.configFlag)
	}
	for _, a := range c.initArgs {
		parts = append(parts, shellQuote(a))
	}
	if change != "" {
		parts = append(parts, change)
	}
	return strings.Join(parts, " ")
}

// InitPortal is Init with the saved flags minus --dev-local-pages and
// --passkey-origin, so the engine moves to the portal's pages, plus
// --add-passkey: a passkey made on development pages cannot sign there.
func (c Commands) InitPortal() string {
	args := make([]string, 0, len(c.initArgs))
	for i := 0; i < len(c.initArgs); i++ {
		a := c.initArgs[i]
		name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		drop := name == flagDevLocalPages || name == flagPasskeyOrigin
		if !drop {
			args = append(args, a)
		}
		if !hasValue && i+1 < len(c.initArgs) {
			i++ // the flag's value is the next argument
			if !drop {
				args = append(args, c.initArgs[i])
			}
		}
	}
	c.initArgs = args
	return c.Init("--add-passkey")
}

// ErrBadTable is a table name Grant refuses: not a plain schema.table, so it
// could add a second table to the list or break the command's quoting.
var ErrBadTable = errors.New("not a plain schema.table name")

var plainTable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*$`)

// Grant is init with the saved flags and table added to the agent's access
// list: flag is "read" or "write". A saved list is extended, never replaced
// (init takes the last value of a flag). Two Grants do not stack: each is
// the saved flags plus its one table. The table must be a plain,
// schema-qualified name: a list separator or a quote could add another table.
func (c Commands) Grant(flag, table string) (string, error) {
	g, err := c.granted(flag, table)
	if err != nil {
		return "", err
	}
	return g.Init(""), nil
}

// RemoteGrant is InitRemote with table added to the agent's access list,
// as Grant adds it.
func (c Commands) RemoteGrant(flag, table string) (string, error) {
	g, err := c.granted(flag, table)
	if err != nil {
		return "", err
	}
	return g.InitRemote(""), nil
}

// granted is c with table added to the saved flag's list.
func (c Commands) granted(flag, table string) (Commands, error) {
	if !plainTable.MatchString(table) {
		return Commands{}, fmt.Errorf("%w: %q", ErrBadTable, table)
	}
	args := append([]string(nil), c.initArgs...)
	merged := false
	for i := 0; i < len(args) && !merged; i++ {
		name, value, hasValue := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		switch {
		case name != flag:
		case hasValue:
			args[i], merged = "--"+flag+"="+value+","+table, true
		case i+1 < len(args):
			args[i+1], merged = args[i+1]+","+table, true
		}
	}
	if !merged {
		args = append(args, "--"+flag+"="+table)
	}
	c.initArgs = args
	return c, nil
}

// remoteInitFlags are the saved init flags basalt init --remote takes; the
// others (--os-user, --socket-dir and the like) are init's own and
// --remote refuses them.
var remoteInitFlags = map[string]bool{
	flagAgent: true, flagWrite: true, flagRead: true, "prefix": true, "statement-timeout": true, "operated-by": true,
}

// InitRemote is basalt init --remote on the engine's machine with the saved
// flags it takes plus change (for example "--new-code"). It makes a setup
// code and never asks for the admin connection string (CO-9). On an
// agent-operated engine it ends with --json: the agent follows the
// personMessage and nextSteps it prints (CONTRACT.md, Setup code steps).
func (c Commands) InitRemote(change string) string {
	parts := []string{cmdBasalt, "init", "--remote"}
	if !c.hasAgentFlag() {
		parts = append(parts, "--agent", c.agent)
	}
	if c.configFlag != "" {
		parts = append(parts, c.configFlag)
	}
	for i := 0; i < len(c.initArgs); i++ {
		a := c.initArgs[i]
		name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		keep := remoteInitFlags[name]
		if keep {
			parts = append(parts, shellQuote(a))
		}
		if !hasValue && i+1 < len(c.initArgs) {
			i++ // the flag's value is the next argument
			if keep {
				parts = append(parts, shellQuote(c.initArgs[i]))
			}
		}
	}
	if change != "" {
		parts = append(parts, change)
	}
	if c.agentOperated {
		parts = append(parts, "--json")
	}
	return strings.Join(parts, " ")
}

// SetupCode is what the person runs on their own computer to apply a setup
// code: basalt init --setup-code takes no --agent or --config, since it
// writes no engine config (CONTRACT.md, basalt init --setup-code).
func SetupCode(code string) string { return "basalt init --setup-code " + code }

// RevertDryRun is the person's command that prepares the revert of scope
// without signing it and prints what it would do.
func (c Commands) RevertDryRun(scope guard.RevertScope) string {
	return c.verb("revert", "--"+strings.ToLower(string(scope.Kind)), scope.ID.String(), "--dry-run")
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
	return strings.Join(append([]string{cmdBasalt, verb, c.flags}, args...), " ")
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
