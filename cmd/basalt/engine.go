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
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

// runEngine runs the engine service; the launchd or systemd unit starts it.
func runEngine(ctx context.Context, args []string, io stdio) int {
	fs := flag.NewFlagSet("engine", flag.ContinueOnError)
	fs.SetOutput(io.err)
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return exitUsage
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(io.err, "engine", err)
	}
	log := slog.New(slog.NewTextHandler(io.err, nil))
	if err := engine.Run(ctx, cfg, configArg(*configPath), log); err != nil {
		return fail(io.err, "engine", err)
	}
	return exitOK
}

// configArg is the --config argument a person's basalt command needs to
// find this engine config: empty for the default path, else the absolute
// path, quoted for a shell.
func configArg(path string) string {
	if path == config.DefaultPath(runtime.GOOS) {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return "--config " + shellQuote(path)
}

// runMCP is the agent's MCP server: a relay from stdio to the agent's engine
// socket. It never loads the SQL parser or a credential.
func runMCP(ctx context.Context, args []string, io stdio) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.err)
	agent := fs.String("agent", "", "agent name (socket <socket-dir>/<agent>.sock)")
	socketDir := fs.String("socket-dir", config.DefaultSocketDir(runtime.GOOS), "engine socket directory")
	socket := fs.String("socket", "", "engine socket path (overrides --agent)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return exitUsage
	}
	path := *socket
	if path == "" {
		if !config.ValidAgentName(*agent) {
			fs.Usage()
			return exitUsage
		}
		path = config.SocketPath(*socketDir, *agent)
	}
	if err := shim.Relay(ctx, path, io.in, io.out); err != nil {
		return fail(io.err, "mcp", err)
	}
	return exitOK
}

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
	fs.StringVar(&a.approvalPage, "approval-page", "", "install --agent: the approval page (development origin)")
	credStdin := fs.Bool("credential-stdin", false, "install --agent: read the agent's connection string from stdin")
	if fs.Parse(args[1:]) != nil || fs.NArg() > 0 {
		return exitUsage
	}
	bin, err := binaryPath(*binary)
	if err != nil {
		return fail(io.err, "service", err)
	}
	spec := service.Spec{GOOS: runtime.GOOS, Binary: bin, ConfigPath: *configPath, User: *user}
	if action == "install" && a.name != "" {
		spec, err = agentSpecFromStdin(io.in, spec, a, *credStdin, *dryRun)
		if err != nil {
			return fail(io.err, "service", err)
		}
	}
	sys := service.OSSystem{Stdout: io.out, Stderr: io.err}

	steps, err := service.UninstallPlan(spec)
	if action == "install" {
		steps, err = service.InstallPlan(ctx, sys, spec)
	}
	if err != nil {
		return fail(io.err, "service", err)
	}
	if err := service.Apply(ctx, sys, steps, *dryRun, io.out); err != nil {
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
	case !credStdin:
		return spec, errors.New("--agent needs --credential-stdin; the credential never goes on the command line")
	}
	if _, err := user.Lookup(a.osUser); err != nil {
		return spec, fmt.Errorf("os user %q: %w", a.osUser, err)
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
