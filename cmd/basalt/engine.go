package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/lib/logredact"
	"github.com/basaltdbhq/basaltdb/internal/links/in/linkscli"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// runEngine runs the engine service; the launchd or systemd unit starts it.
func runEngine(ctx context.Context, args []string, io cli.Stdio) int {
	return runEngineOn(ctx, args, io, osHost{})
}

// runEngineOn is runEngine with the host that tells root and the config dir.
func runEngineOn(ctx context.Context, args []string, io cli.Stdio, h cli.Machine) int {
	fs := cli.NewFlagSet("engine")
	fs.SetOutput(io.Err)
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	pluginDebug := fs.Bool("plugin-debug", false, "show local plugins' stderr on this terminal (a foreground engine only; never logged)")
	supervised := fs.Bool("supervise", false, "run the engine as a child and restart it when it crashes")
	startedBy := fs.String("started-by", startedByHand, "why this engine started: hand, mcp or crash (set by basalt mcp and --supervise)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return cli.ExitUsage
	}
	if !slices.Contains([]string{startedByHand, engine.StartedByMCP, engine.StartedByCrash}, *startedBy) {
		_, _ = fmt.Fprintf(io.Err, "basalt engine: --started-by is hand, mcp or crash, not %q\n", *startedBy)
		return cli.ExitUsage
	}
	if *supervised && *pluginDebug {
		_, _ = fmt.Fprintln(io.Err, "basalt engine: --plugin-debug shows a foreground engine's plugin output; drop --supervise to use it")
		return cli.ExitUsage
	}
	*configPath = cli.ConfigOrFallback(h, fs, *configPath)
	// Started as root, the hardened read: the config's
	// directory may belong to another user, who could plant a link there.
	if *supervised {
		return enginecli.RunSupervise(ctx, engine.EnginePath(*configPath), *startedBy, io, h, engineCLIHost{}, engineHost{}, engineTerminal{}, app.BinaryWatch{})
	}
	// A supervised child on macOS stops when its supervisor dies.
	watchSupervisedParent(ctx)
	log := engineLog(io.Err)
	// handed is the setup page's listener of an engine that waited for its
	// config: the first run serves its own pages on it.
	var handed net.Listener
	if engine.WaitsForConfig(engineTerminal{}, h.Euid(), engine.EnginePath(*configPath)) {
		ln, err := app.WaitForConfig(ctx, app.WaitOptions{Addr: app.SetupAddr, Origin: app.SetupOrigin, ConfigPath: *configPath, Log: log})
		if err != nil {
			if ctx.Err() != nil {
				return cli.ExitOK
			}
			return fail(io.Err, "engine", err)
		}
		handed = ln
	}
	cfg, err := cli.LoadEngineConfigAs(appShell{}, h.Euid(), *configPath)
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	run := func(ctx context.Context, r engine.Restart) error {
		o := app.RestartOptions{Restart: r}
		o.StartedBy = *startedBy
		o.PagesListener, handed = handed, nil
		if *pluginDebug {
			o.PluginStderr = io.Err
		}
		return app.RunWith(ctx, cfg, engine.EnginePath(*configPath), log, o)
	}
	// A reload (a connect-only agent's setup changed) serves the config as
	// it is now.
	reload := func() error {
		next, err := cli.LoadEngineConfigAs(appShell{}, h.Euid(), *configPath)
		if err != nil {
			return err
		}
		cfg = next
		return nil
	}
	if err := engine.ServeRestarting(ctx, run, app.OSRestart(log), reload, log); err != nil {
		return fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}

// runMCP is the agent's MCP server: a relay from stdio to the agent's engine
// socket. It never reads a credential or reaches a database. While the
// socket does not answer it serves status and the tool list itself and
// answers every other call UNAVAILABLE ENGINE_UNREACHABLE (CONTRACT.md, Next
// steps, Startup failures).
func runMCP(ctx context.Context, args []string, io cli.Stdio) int {
	return enginecli.RunMCPOn(ctx, args, io, osHost{}, engineCLIHost{})
}

// engineDownServer is what basalt mcp answers while the engine is down.
func engineDownServer(name, configPath string, log *slog.Logger) (app.EngineDownServer, error) {
	down, err := engineDown(name, configPath, log)
	if err != nil {
		return app.EngineDownServer{}, err
	}
	return app.NewEngineDownServer(down), nil
}

// engineDown is what basalt mcp answers with while the engine is down, with
// the config it could read, as the agent's own user (the shim never runs as
// root).
func engineDown(name, configPath string, log *slog.Logger) (agent.EngineDown, error) {
	var cfg *config.Config
	c, cfgErr := config.Load(configPath)
	if cfgErr == nil {
		cfg = &c
	}
	cmds, err := shimCommands(name, configPath, cfg)
	if err != nil {
		return agent.EngineDown{}, err
	}
	return agent.EngineDown{Name: name, Commands: cmds, Config: cfg, ConfigErr: cfgErr, Log: log, Now: time.Now, ConfigPath: configPath, Host: app.AgentEngineHost()}, nil
}

func shimCommands(name, configPath string, cfg *config.Config) (guidance.Commands, error) {
	if !config.ValidAgentName(name) {
		name = fallbackAgentName
	}
	cmds, err := agent.NewCommands(name, configPath, runtime.GOOS, app.AgentServiceManager())
	if err != nil || cfg == nil {
		return cmds, err
	}
	if !cfg.Service() {
		cmds = cmds.Foreground()
	}
	return cmds, nil
}

// refuseSecretInitArgs refuses --init-arg values that look like a
// connection string or carry a password. None is saved or replayed.
func refuseSecretInitArgs(args []string) error {
	for _, a := range args {
		lower := strings.ToLower(a)
		if strings.Contains(lower, "password=") {
			return fmt.Errorf("saved init argument %q carries a password", a)
		}
		if _, rest, ok := strings.Cut(a, "://"); ok && strings.Contains(rest, "@") {
			return fmt.Errorf("saved init argument %q looks like a connection string", a)
		}
	}
	return nil
}

// fallbackAgentName names the agent in commands when basalt mcp was given a
// socket whose name is not an agent name.
const fallbackAgentName = "agent"

// runService is basalt service for the command table.
func runService(ctx context.Context, args []string, io cli.Stdio) int {
	return enginecli.RunService(ctx, args, io, engineCLIHost{})
}

// runServiceAt is runService on the engine config at configPath: the
// service's engine always runs on the system path (tests give their own).
func runServiceAt(ctx context.Context, args []string, io cli.Stdio, configPath string) int {
	if len(args) == 0 || args[0] != "install" {
		fail(io.Err, "service", errors.New("want install"))
		return cli.ExitUsage
	}
	action := args[0]
	fs := cli.NewFlagSet("service " + action)
	fs.SetOutput(io.Err)
	user := fs.String("user", app.OSDefaultUser(runtime.GOOS), "OS user the engine runs as")
	binary := fs.String("binary", "", "absolute path of the basalt binary (default: this binary)")
	dryRun := fs.Bool("dry-run", false, "print the steps without running them")
	var a agentInstall
	fs.StringVar(&a.name, "agent", "", "install: also place this agent (basalt init runs this under sudo)")
	fs.StringVar(&a.osUser, "os-user", "", "install --agent: the agent's OS user")
	linkscli.PagesURLFlag(fs, &a.pagesURL, "install --agent: the pages base URL the agent's passkey belongs to")
	fs.BoolVar(&a.devLocalPages, flagDevLocalPages, false, "install --agent: the config's devLocalPages, as basalt init --dev-local-pages sets it")
	fs.Func(flagVault, "install --agent: on or off, the config's vault as the person chose it (default: keep the config's)", func(v string) error {
		var m setup.VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.vault = m.Enum()
		return nil
	})
	fs.Func(flagVaultDefault, "install --agent: on or off, the config's vault only when it has none yet", func(v string) error {
		var m setup.VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.vaultDefault = m.Enum()
		return nil
	})
	fs.Func("operated-by", "install --agent: person or agent, the config's operatedBy (default: keep the config's)", func(v string) error {
		var o OperatedBy
		if err := o.Set(v); err != nil {
			return err
		}
		a.operatedBy = o.enum()
		return nil
	})
	fs.Func(flagInitArg, "install --agent: ignored, kept for older install scripts; refused when it holds a secret (repeatable)", func(v string) error {
		a.initArgs = append(a.initArgs, v)
		return nil
	})
	fs.Func(flagPersonUID, "install --agent: an OS user id of the person (repeatable; default: SUDO_UID)", func(v string) error {
		uid, err := parseUID(v)
		if err != nil {
			return err
		}
		a.personUIDs = append(a.personUIDs, uid)
		return nil
	})
	fs.BoolVar(&a.keepCredential, flagKeepCredential, false, "install --agent: keep the agent's credential file (its role kept its password)")
	credStdin := fs.Bool("credential-stdin", false, "install --agent: read the agent's connection string from stdin")
	if fs.Parse(args[1:]) != nil || fs.NArg() > 0 {
		return cli.ExitUsage
	}
	if a.keepCredential && *credStdin {
		fail(io.Err, "service", errors.New("--keep-credential and --credential-stdin cannot be used together"))
		return cli.ExitUsage
	}
	bin, err := cli.BinaryPath(*binary)
	if err != nil {
		return fail(io.Err, "service", err)
	}
	spec := app.OSSpec{GOOS: runtime.GOOS, Binary: bin, ConfigPath: configPath, User: *user}
	// The unit's memory limits follow the installed config's
	// pii.maxMemoryMB (the default when there is none yet), so running
	// install again after raising it rewrites them.
	if cfg, err := config.LoadNoFollow(configPath); err == nil {
		spec.MemoryMB = cfg.PIIOrDefault().MaxMemoryMB
	}
	// lock is the config lock basalt service install --agent holds.
	var lock *config.HeldLock
	if action == "install" && a.name != "" {
		if a.devLocalPages {
			_, _ = fmt.Fprintln(io.Err, "basalt: "+config.DevLocalPagesWarning)
		}
		if len(a.personUIDs) == 0 && os.Getenv(envSudoUID) != "" {
			uid, err := parseUID(os.Getenv(envSudoUID))
			if err != nil {
				return fail(io.Err, "service", fmt.Errorf("%s: %w", envSudoUID, err))
			}
			a.personUIDs = []uint32{uid}
		}
		if !*dryRun {
			a.report = func(v config.VaultWritten) { _, _ = fmt.Fprint(io.Err, a.vaultChoice().Line(v)) }
			// Hold the config lock from reading engine.json until the new
			// one is in place, as every config writer does; the lock file
			// goes to the engine's user (CONTRACT.md, Lock files).
			held, err := config.LockConfigAs(configPath, app.OSLookupUID(*user))
			if err != nil {
				return fail(io.Err, "service", err)
			}
			defer held.Release()
			lock = &held
		}
		spec, err = agentSpecFromStdin(io.In, spec, a, *credStdin, *dryRun)
		if err != nil {
			return fail(io.Err, "service", err)
		}
	}
	if cfg, err := config.LoadNoFollow(configPath); err == nil {
		// Every local plugin entry runs under its own unit and OS user:
		// install writes them all again.
		spec = withPluginUnits(spec, cfg, io.Err)
	} else if !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(io.Err, "basalt: %s cannot be read, so plugin service units are left as they are\n", configPath)
	}
	sys := app.OSExecSystem{Stdout: io.Out, Stderr: io.Err}

	steps, err := app.OSInstallPlan(ctx, sys, spec)
	if err != nil {
		return fail(io.Err, "service", err)
	}
	if err := app.OSSettle(app.OSApply(ctx, sys, steps, *dryRun, io.Out), sys, runtime.GOOS); err != nil {
		return fail(io.Err, "service", err)
	}
	// The install may have just made the engine's user.
	if lock != nil {
		if err := lock.HandTo(app.OSLookupUID(*user)); err != nil {
			return fail(io.Err, "service", fmt.Errorf("give %s.lock to %s: %w", configPath, *user, err))
		}
	}
	return cli.ExitOK
}

// maxCredentialBytes bounds the connection string read from stdin.
const maxCredentialBytes = 4096

// agentSpecFromStdin is basalt service install --agent: the agent and its
// credential (one line on stdin, never an argument) go into the service's
// own directories, owned by the engine's user.
func agentSpecFromStdin(in io.Reader, spec app.OSSpec, a agentInstall, credStdin, dryRun bool) (app.OSSpec, error) {
	switch {
	case !config.ValidAgentName(a.name):
		return spec, fmt.Errorf("agent name %q is not valid", a.name)
	case a.osUser == "":
		return spec, errors.New("--agent needs --os-user")
	case !credStdin && !a.keepCredential:
		return spec, errors.New("--agent needs --credential-stdin; the credential never goes on the command line")
	}
	// Init's saved flags go into engine.json: hold them to what the engine
	// accepts (no connection URL, no password) before anything is written.
	cfgPath, err := filepath.Abs(spec.ConfigPath)
	if err != nil {
		return spec, err
	}
	if _, err := agent.NewCommands(a.name, cfgPath, spec.GOOS, app.AgentServiceManager()); err != nil {
		return spec, err
	}
	if err := refuseSecretInitArgs(a.initArgs); err != nil {
		return spec, fmt.Errorf("--init-arg: %w", err)
	}
	if _, err := user.Lookup(a.osUser); err != nil {
		return spec, fmt.Errorf("os user %q: %w", a.osUser, err)
	}
	if err := checkAgentOSUser(a.osUser, spec.User); err != nil {
		return spec, err
	}
	if err := checkServicePersons(a.personUIDs, spec.User); err != nil {
		return spec, err
	}
	if a.keepCredential {
		return keptCredentialSpec(spec, a, dryRun)
	}
	line, err := bufio.NewReader(io.LimitReader(in, maxCredentialBytes)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return spec, err
	}
	a.dsn = strings.TrimSpace(line)
	if a.dsn == "" && !dryRun {
		return spec, errors.New("no connection string on stdin")
	}
	return agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
}

// keptCredentialSpec is the install when the agent's role kept its password:
// the existing credential file must exist. It is written back unchanged, so
// it is owned by the engine's user even when the user changed.
func keptCredentialSpec(spec app.OSSpec, a agentInstall, dryRun bool) (app.OSSpec, error) {
	cred := filepath.Join(filepath.Dir(spec.ConfigPath), "agents", a.name+".url")
	raw, err := readKeptCredential(appSetupHost{}, cred, spec.User)
	if err != nil && waitingForAddress(spec, a.name, cred) {
		// A connect-only setup waits for its address: no credential yet,
		// and the engine writes it after the person's YES (CONTRACT.md,
		// Connect-only setup codes), with the password in .secret, which
		// must be the engine user's own for that.
		if _, serr := readKeptCredential(appSetupHost{}, config.SecretPath(cred, a.name), spec.User); serr != nil && !dryRun {
			return spec, fmt.Errorf("agent %s waits for its database's address, but its .secret is not usable by the engine's user %s (%w); run basalt init --remote as that user", a.name, spec.User, serr)
		}
		a.keepCredential, a.waiting = true, true
		return agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
	}
	if err != nil && !dryRun {
		return spec, fmt.Errorf("the agent's role keeps its password but its credential file %s is not usable (%w); run basalt init --rotate-password", cred, err)
	}
	a.dsn, a.keepCredential = raw, false
	return agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
}

// waitingForAddress reports whether the config gives agent name a pending
// connect-only setup and no credential file exists at cred: the agent
// waits for its database's address.
func waitingForAddress(spec app.OSSpec, name, cred string) bool {
	cfg, err := cli.LoadEngineConfigAs(appShell{}, os.Geteuid(), spec.ConfigPath)
	if err != nil {
		return false
	}
	for _, ag := range cfg.Agents {
		if ag.Name == name && ag.Setup != nil && ag.Setup.ConnectOnly() {
			_, err := os.Lstat(cred)
			return errors.Is(err, os.ErrNotExist)
		}
	}
	return false
}

// checkServicePersons refuses a service install without a person uid, or
// with root or the engine's own OS user among them (CONTRACT.md, CLI,
// Recording the person).
func checkServicePersons(uids []uint32, engineUser string) error {
	if err := checkPersons(uids); err != nil {
		return err
	}
	u, err := user.Lookup(engineUser)
	if err != nil {
		return nil //nolint:nilerr // the engine's user does not exist yet: the install creates it, with a new uid
	}
	for _, uid := range uids {
		if strconv.FormatUint(uint64(uid), 10) == u.Uid {
			return fmt.Errorf("--person-uid %d is the engine's own OS user %s; give the person's", uid, engineUser)
		}
	}
	return nil
}

// engineLog is the engine's and basalt mcp's log on w: a text handler that
// scrubs link secrets from what it writes (logredact).
func engineLog(w io.Writer) *slog.Logger { return slog.New(logredact.NewTextHandler(w, nil)) }
