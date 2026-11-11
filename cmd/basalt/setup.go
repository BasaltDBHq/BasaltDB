package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// After the guard and the passkey, basalt init sets up the engine one of
// two ways, decided once:
//
//   - as a background service under its own OS user (the default, asked
//     at the terminal): one sudo elevation runs basalt service install
//     with the agent, which writes the config and the credential into the
//     service's system directories owned by that user, installs and
//     starts the unit; init then checks the engine answers on the socket.
//   - in the foreground as the person (--no-service, an answer of no, a
//     non-terminal without --yes, or paths given with --config,
//     --socket-dir or --credential-file): init writes the config and
//     credential where the person can, and prints the one command.

// perUserDirName is the per-user config directory under os.UserConfigDir.
const perUserDirName = "basalt"

// setupEngine is init's last step.
func setupEngine(c *cliIO, f initFlags, dsn string) error {
	asService, err := chooseService(c, f)
	if err != nil {
		return err
	}
	if asService {
		if err := installService(c, f, dsn); err != nil {
			return fmt.Errorf("the guard is installed but the engine service is not (run basalt init again, or with --no-service): %w", err)
		}
		return offerClaude(c, f)
	}
	f, err = perUserPaths(c, f)
	if err != nil {
		return err
	}
	if err := register(c, f, dsn); err != nil {
		return fmt.Errorf("the guard is installed but the engine config was not written (run init again to rotate the credential): %w", err)
	}
	fmt.Fprintf(c.stderr, "basalt: credential %s; engine config %s\n", f.credFile, f.configPath)
	fmt.Fprint(c.stderr, foregroundNext(f, c.goos))
	return offerClaude(c, f)
}

// chooseService decides between the service and the foreground engine.
func chooseService(c *cliIO, f initFlags) (bool, error) {
	switch {
	case f.noService || f.pathsGiven:
		return false, nil
	case f.yes:
		return true, nil
	case !c.interactive:
		fmt.Fprintln(c.stderr, "basalt: not at a terminal, so the engine service is not installed (pass --yes to install it)")
		return false, nil
	}
	question := fmt.Sprintf("Install the engine as a background service? This creates the OS user %s", f.engineUser)
	if c.host.Euid() != 0 {
		question += " and needs your password once."
	}
	return c.confirmYes(question)
}

// perUserPaths moves a foreground setup that kept the system defaults to
// the person's config directory, which they can write without sudo.
func perUserPaths(c *cliIO, f initFlags) (initFlags, error) {
	if f.pathsGiven || c.host.Euid() == 0 {
		return f, nil
	}
	base, err := c.host.UserConfigDir()
	if err != nil {
		return f, err
	}
	dir := filepath.Join(base, perUserDirName)
	f.configPath = filepath.Join(dir, "engine.json")
	f.socketDir = filepath.Join(dir, "run")
	f.credFile = filepath.Join(dir, "agents", f.agent+".url")
	if err := config.CheckSocketPath(config.SocketPath(f.socketDir, f.agent)); err != nil {
		return f, fmt.Errorf("%w; pass --socket-dir", err)
	}
	return f, nil
}

// register writes the credential file and adds the agent to the engine
// config (foreground setup).
func register(c *cliIO, f initFlags, dsn string) error {
	if err := config.WriteFile(f.credFile, []byte(dsn+"\n")); err != nil {
		return err
	}
	return config.UpsertAgent(f.configPath, engineSettings(f, c.goos), config.Agent{
		Name: f.agent, OSUser: f.osUser, CredentialFile: f.credFile,
	})
}

// foregroundNext is the one command that starts the engine, and the MCP
// server line.
func foregroundNext(f initFlags, goos string) string {
	return fmt.Sprintf("next, start the engine; it runs in the foreground as you (same-user mode: writes are guarded, but your OS user can read the credential):\n  basalt engine --config %s\n%s",
		shellQuote(f.configPath), mcpLine(f, goos))
}

// mcpLine is the MCP server command for the agent's client.
func mcpLine(f initFlags, goos string) string {
	return fmt.Sprintf("then add this MCP server to the agent's client, running as OS user %s (docs/mcp-clients.md):\n  %s\n",
		f.osUser, shellJoin(mcpArgs(f, goos, "basalt")))
}

// mcpArgs is basalt mcp for the agent, with bin as the program.
func mcpArgs(f initFlags, goos, bin string) []string {
	return append([]string{bin, "mcp", "--agent", f.agent}, socketDirArgs(f, goos)...)
}

// shellJoin quotes each argument for display.
func shellJoin(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, shellQuote(a))
	}
	return strings.Join(out, " ")
}

// agentInstall is the agent basalt service install places for the engine.
type agentInstall struct {
	name, osUser, pagesURL, dsn string
}

// agentServiceSpec is the service install spec with the agent's files in
// the service's own directories: the engine config (the existing one with
// the agent upserted) and the credential, both owned by the engine's user.
// For a plan that is only printed, contents are left out.
func agentServiceSpec(goos, bin, configPath, engineUser string, a agentInstall, printOnly bool) (service.Spec, error) {
	spec := service.Spec{GOOS: goos, Binary: bin, ConfigPath: configPath, User: engineUser}
	cred := filepath.Join(filepath.Dir(configPath), "agents", a.name+".url")
	spec.Files = []service.File{{Path: configPath}, {Path: cred}}
	if printOnly {
		return spec, nil
	}
	raw, err := config.Upserted(configPath,
		config.Settings{SocketDir: config.DefaultSocketDir(goos), PagesURL: a.pagesURL},
		config.Agent{Name: a.name, OSUser: a.osUser, CredentialFile: cred})
	if err != nil {
		return spec, err
	}
	spec.Files[0].Content = raw
	spec.Files[1].Content = []byte(a.dsn + "\n")
	return spec, nil
}

// serviceInstallArgs is the one command init runs under sudo. The
// credential goes on its stdin, never on the command line.
func serviceInstallArgs(f initFlags, bin string) []string {
	args := []string{bin, "service", "install", "--config", f.configPath, "--user", f.engineUser,
		"--agent", f.agent, "--os-user", f.osUser}
	if f.passkeyOrigin != "" {
		args = append(args, "--pages-url", f.passkeyOrigin)
	}
	return append(args, "--credential-stdin")
}

// installService installs the engine service with the agent in one
// elevation, then checks the engine answers on the agent's socket.
func installService(c *cliIO, f initFlags, dsn string) error {
	if err := elevateInstall(c, f, dsn); err != nil {
		return err
	}
	socket := config.SocketPath(config.DefaultSocketDir(c.goos), f.agent)
	if me, _ := invokingUser(); me != f.osUser {
		// The engine admits only the agent's OS user on its socket.
		fmt.Fprintf(c.stderr, "basalt: engine service installed as %s; check it as %s with the MCP command below\n", f.engineUser, f.osUser)
		fmt.Fprint(c.stderr, mcpLine(f, c.goos))
		return nil
	}
	if err := c.host.Probe(c.ctx, socket); err != nil {
		return fmt.Errorf("the engine did not answer on %s (%w); see %s", socket, err, engineLogHint(c.goos))
	}
	fmt.Fprintf(c.stderr, "basalt: engine running as %s; it answered on %s\n", f.engineUser, socket)
	fmt.Fprint(c.stderr, mcpLine(f, c.goos))
	return nil
}

// elevateInstall runs the service install with the agent: in this process
// when init already runs as root, else as one sudo command.
func elevateInstall(c *cliIO, f initFlags, dsn string) error {
	bin, err := c.host.Executable()
	if err != nil {
		return err
	}
	if c.host.Euid() == 0 {
		return applyServiceInstall(c, bin, f.configPath, f.engineUser,
			agentInstall{name: f.agent, osUser: f.osUser, pagesURL: f.passkeyOrigin, dsn: dsn}, false)
	}
	fmt.Fprintln(c.stderr, "basalt: installing the engine service with sudo:")
	return c.host.Sudo(c.ctx, serviceInstallArgs(f, bin), dsn+"\n", c.stderr, c.stderr)
}

// applyServiceInstall builds and runs (or only prints) the service install
// with an agent. basalt service install runs it under sudo; init runs it
// itself when already root.
func applyServiceInstall(c *cliIO, bin, configPath, engineUser string, a agentInstall, printOnly bool) error {
	spec, err := agentServiceSpec(c.goos, bin, configPath, engineUser, a, printOnly)
	if err != nil {
		return err
	}
	sys := c.host.System(c.stderr, c.stderr)
	steps, err := service.InstallPlan(c.ctx, sys, spec)
	if err != nil {
		return err
	}
	return service.Apply(c.ctx, sys, steps, printOnly, c.stderr)
}

func engineLogHint(goos string) string {
	if goos == "darwin" {
		return "/Library/Logs/Basalt/engine.log"
	}
	return "journalctl -u " + service.SystemdUnitName
}

// claudeServerPrefix names the agent's server in Claude Code.
const claudeServerPrefix = "basalt-"

// offerClaude asks, at a terminal and only when the claude CLI is on PATH,
// to add the agent's MCP server to Claude Code. Never without a yes, and
// not when Claude Code already has a server of that name (claude mcp get
// succeeds), where claude mcp add would fail.
func offerClaude(c *cliIO, f initFlags) error {
	if !c.interactive {
		return nil
	}
	claude, err := c.host.LookPath("claude")
	if err != nil {
		return nil //nolint:nilerr // no claude CLI: nothing to offer
	}
	bin, err := c.host.Executable()
	if err != nil {
		return err
	}
	name := claudeServerPrefix + f.agent
	if c.host.Run(c.ctx, []string{claude, "mcp", "get", name}, io.Discard, io.Discard) == nil {
		fmt.Fprintf(c.stderr, "basalt: Claude Code already has %s\n", name)
		return nil
	}
	args := append([]string{claude, "mcp", "add", name, "--"}, mcpArgs(f, c.goos, bin)...)
	shown := shellJoin(append([]string{"claude"}, args[1:]...))
	ok, err := c.confirmYes(fmt.Sprintf("Add it to Claude Code now (%s)?", shown))
	if err != nil || !ok {
		return err
	}
	if err := c.host.Run(c.ctx, args, c.stderr, c.stderr); err != nil {
		return errors.New("claude mcp add failed; add the server by hand with the line above")
	}
	return nil
}

func socketDirArgs(f initFlags, goos string) []string {
	if f.socketDir == config.DefaultSocketDir(goos) {
		return nil
	}
	return []string{"--socket-dir", f.socketDir}
}
