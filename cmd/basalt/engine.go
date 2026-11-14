package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/privdrop"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

// runEngine runs the engine service; the launchd or systemd unit starts it.
func runEngine(ctx context.Context, args []string, io stdio) int {
	return runEngineOn(ctx, args, io, osHost{})
}

// runEngineOn is runEngine with the host that tells root and the config dir.
func runEngineOn(ctx context.Context, args []string, io stdio, h host) int {
	fs := flag.NewFlagSet("engine", flag.ContinueOnError)
	fs.SetOutput(io.err)
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	runAs := fs.String("user", "", "start as root, then run as this OS user before reading the config (a container without systemd)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return exitUsage
	}
	if *runAs != "" {
		if err := dropToUser(privdrop.OS{}, *runAs, io.err); err != nil {
			return fail(io.err, "engine", err)
		}
		// The inherited HOME is still root's; look in the engine user's own.
		h = engineUserHost{host: h, name: *runAs}
	}
	// After the drop, so a bot's own user finds the config init left.
	*configPath = configOrFallback(h, fs, *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(io.err, "engine", err)
	}
	log := slog.New(slog.NewTextHandler(io.err, nil))
	if err := engine.Run(ctx, cfg, enginePath(*configPath), log); err != nil {
		return fail(io.err, "engine", err)
	}
	return exitOK
}

// dropToUser is basalt engine --user: before the config, the credential, a
// socket or a port is opened, the engine makes its directories, gives up
// root for name and checks it cannot get it back (CONTRACT.md, CLI).
// engineUserHost is a host whose config directory is the home of the OS
// user the engine dropped to, not the HOME it inherited from root.
type engineUserHost struct {
	host
	name string
}

func (h engineUserHost) UserConfigDir() (string, error) {
	u, err := user.Lookup(h.name)
	if err != nil {
		return "", err
	}
	return userConfigDirIn(runtime.GOOS, u.HomeDir)
}

// userConfigDirIn is os.UserConfigDir for a user whose home is home.
func userConfigDirIn(goos, home string) (string, error) {
	if home == "" {
		return "", errors.New("the engine user has no home directory")
	}
	if goos == "darwin" {
		return filepath.Join(home, "Library", "Application Support"), nil
	}
	return filepath.Join(home, ".config"), nil
}

func dropToUser(sys privdrop.System, name string, w io.Writer) error {
	res, err := privdrop.Drop(sys, name, engineDirs(runtime.GOOS))
	if err != nil {
		return err
	}
	a := res.Account
	how := "already running as"
	if res.Dropped {
		how = "dropped root; running as"
	}
	_, _ = fmt.Fprintf(w, "basalt engine: %s %s (uid %d, gid %d)%s\n", how, a.Name, a.UID, a.GID, noNewPrivsNote(runtime.GOOS))
	return nil
}

// noNewPrivsNote says whether the kernel's no_new_privs is set on goos.
func noNewPrivsNote(goos string) string {
	if goos == "linux" {
		return "; no_new_privs set"
	}
	return ""
}

// engineDirs are the engine's directories as privdrop makes them.
func engineDirs(goos string) []privdrop.Dir {
	dirs := service.EngineDirs(goos)
	out := make([]privdrop.Dir, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, privdrop.Dir{Path: d.Path, Mode: d.Mode})
	}
	return out
}

// enginePath is the absolute path of the engine config, which the engine
// names in the commands it gives the person.
func enginePath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// runMCP is the agent's MCP server: a relay from stdio to the agent's engine
// socket. It never reads a credential or reaches a database. While the
// socket does not answer it serves status and the tool list itself and
// answers every other call UNAVAILABLE ENGINE_UNREACHABLE (CONTRACT.md, Next
// steps, Startup failures).
func runMCP(ctx context.Context, args []string, io stdio) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.err)
	name := fs.String("agent", "", "agent name (socket <socket-dir>/<agent>.sock)")
	socketDir := fs.String("socket-dir", config.DefaultSocketDir(runtime.GOOS), "engine socket directory")
	socket := fs.String("socket", "", "engine socket path (overrides --agent)")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file, read (when it can be) for status while the engine is down")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return exitUsage
	}
	path := *socket
	if path == "" {
		if !config.ValidAgentName(*name) {
			fs.Usage()
			return exitUsage
		}
		path = config.SocketPath(*socketDir, *name)
	}
	fallback, err := engineDownServer(shimAgent(*name, path), enginePath(*configPath), slog.New(slog.NewTextHandler(io.err, nil)))
	if err != nil {
		return fail(io.err, "mcp", err)
	}
	if err := shim.Serve(ctx, path, fallback, io.in, io.out); err != nil {
		return fail(io.err, "mcp", err)
	}
	return exitOK
}

// shimAgent names the agent in status when basalt mcp was given only a
// socket path: the socket's base name.
func shimAgent(name, socket string) string {
	if name != "" {
		return name
	}
	return strings.TrimSuffix(filepath.Base(socket), ".sock")
}

// engineDownServer is what basalt mcp answers while the engine is down. The
// config is read when the shim's OS user may (same-user mode); a service's
// config is the engine user's alone, and then operatedBy is PERSON and the
// engine starts with the service manager.
func engineDownServer(name, configPath string, log *slog.Logger) (agent.EngineDownServer, error) {
	var cfg *config.Config
	if c, err := config.Load(configPath); err == nil {
		cfg = &c
	}
	cmds, err := shimCommands(name, configPath, cfg)
	if err != nil {
		return agent.EngineDownServer{}, err
	}
	down := agent.EngineDown{Name: name, Commands: cmds, Config: cfg, Log: log, Now: time.Now}
	return down.Server(mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: engine.Instructions}), nil
}

// shimCommands are the agent's commands as far as the shim knows them: the
// saved init flags and the foreground engine when it could read a same-user
// config.
func shimCommands(name, configPath string, cfg *config.Config) (agent.Commands, error) {
	if !config.ValidAgentName(name) {
		name = fallbackAgentName
	}
	if cfg == nil {
		return agent.NewCommands(name, configPath, runtime.GOOS, nil)
	}
	var initArgs []string
	for _, a := range cfg.Agents {
		if a.Name == name {
			initArgs = a.InitArgs
		}
	}
	cmds, err := agent.NewCommands(name, configPath, runtime.GOOS, initArgs)
	if err != nil {
		return agent.NewCommands(name, configPath, runtime.GOOS, nil)
	}
	if !cfg.Service() {
		cmds = cmds.Foreground()
	}
	return cmds, nil
}

// fallbackAgentName names the agent in commands when basalt mcp was given a
// socket whose name is not an agent name.
const fallbackAgentName = "agent"

// runService installs or uninstalls the engine as a system service. It
// prints every step first; --dry-run stops there.
func runService(ctx context.Context, args []string, io stdio) int {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		fail(io.err, "service", errors.New("want install or uninstall"))
		return exitUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	fs.SetOutput(io.err)
	user := fs.String("user", service.DefaultUser(runtime.GOOS), "OS user the engine runs as")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	binary := fs.String("binary", "", "absolute path of the basalt binary (default: this binary)")
	dryRun := fs.Bool("dry-run", false, "print the steps without running them")
	var a agentInstall
	fs.StringVar(&a.name, "agent", "", "install: also place this agent (basalt init runs this under sudo)")
	fs.StringVar(&a.osUser, "os-user", "", "install --agent: the agent's OS user")
	pagesURLFlag(fs, &a.pagesURL, "install --agent: the pages base URL the agent's passkey belongs to")
	fs.BoolVar(&a.devLocalPages, flagDevLocalPages, false, "install --agent: the config's devLocalPages, as basalt init --dev-local-pages sets it")
	fs.Func(flagVault, "install --agent: on or off, the config's vault as the person chose it (default: keep the config's)", func(v string) error {
		var m VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.vault = m.enum()
		return nil
	})
	fs.Func(flagVaultDefault, "install --agent: on or off, the config's vault only when it has none yet", func(v string) error {
		var m VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.vaultDefault = m.enum()
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
	fs.Func(flagInitArg, "install --agent: a flag basalt init saves for the agent (repeatable)", func(v string) error {
		a.initArgs = append(a.initArgs, v)
		return nil
	})
	fs.Func(flagPersonUID, "install --agent: an OS user id the engine's person socket admits (repeatable; default: SUDO_UID)", func(v string) error {
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
		return exitUsage
	}
	if a.keepCredential && *credStdin {
		fail(io.err, "service", errors.New("--keep-credential and --credential-stdin cannot be used together"))
		return exitUsage
	}
	bin, err := binaryPath(*binary)
	if err != nil {
		return fail(io.err, "service", err)
	}
	spec := service.Spec{GOOS: runtime.GOOS, Binary: bin, ConfigPath: *configPath, User: *user}
	// The unit's memory limits follow the installed config's
	// pii.maxMemoryMB (the default when there is none yet), so running
	// install again after raising it rewrites them.
	if cfg, err := config.LoadNoFollow(*configPath); err == nil {
		spec.MemoryMB = cfg.PIIOrDefault().MaxMemoryMB
	}
	if action == "install" && a.name != "" {
		if a.devLocalPages {
			_, _ = fmt.Fprintln(io.err, "basalt: "+config.DevLocalPagesWarning)
		}
		if len(a.personUIDs) == 0 && os.Getenv(envSudoUID) != "" {
			uid, err := parseUID(os.Getenv(envSudoUID))
			if err != nil {
				return fail(io.err, "service", fmt.Errorf("%s: %w", envSudoUID, err))
			}
			a.personUIDs = []uint32{uid}
		}
		if !*dryRun {
			a.report = func(v config.VaultWritten) { _, _ = fmt.Fprint(io.err, a.vaultChoice().line(v)) }
		}
		spec, err = agentSpecFromStdin(io.in, spec, a, *credStdin, *dryRun)
		if err != nil {
			return fail(io.err, "service", err)
		}
	}
	sys := service.OSSystem{Stdout: io.out, Stderr: io.err}

	steps, err := service.UninstallPlan(sys, spec)
	if action == "install" {
		steps, err = service.InstallPlan(ctx, sys, spec)
	}
	if err != nil {
		return fail(io.err, "service", err)
	}
	if err := service.Settle(service.Apply(ctx, sys, steps, *dryRun, io.out), sys, runtime.GOOS); err != nil {
		return fail(io.err, "service", err)
	}
	return exitOK
}

// maxCredentialBytes bounds the connection string read from stdin.
const maxCredentialBytes = 4096

// agentSpecFromStdin is basalt service install --agent: the agent and its
// credential (one line on stdin, never an argument) go into the service's
// own directories, owned by the engine's user.
func agentSpecFromStdin(in io.Reader, spec service.Spec, a agentInstall, credStdin, dryRun bool) (service.Spec, error) {
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
	if _, err := agent.NewCommands(a.name, cfgPath, spec.GOOS, a.initArgs); err != nil {
		return spec, fmt.Errorf("--init-arg: %w", err)
	}
	if _, err := user.Lookup(a.osUser); err != nil {
		return spec, fmt.Errorf("os user %q: %w", a.osUser, err)
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
// it is owned by the engine's user even when --user changed.
func keptCredentialSpec(spec service.Spec, a agentInstall, dryRun bool) (service.Spec, error) {
	cred := filepath.Join(filepath.Dir(spec.ConfigPath), "agents", a.name+".url")
	raw, err := readKeptCredential(cred, spec.User)
	if err != nil && !dryRun {
		return spec, fmt.Errorf("the agent's role keeps its password but its credential file %s is not usable (%w); run basalt init --rotate-password", cred, err)
	}
	a.dsn, a.keepCredential = raw, false
	return agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
}

func binaryPath(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
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
