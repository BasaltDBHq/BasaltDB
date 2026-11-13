package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	f.initArgs = f.savedArgs(c.goos)
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
	f.initArgs = f.savedArgs(c.goos)
	cmds, err := f.commands(c.goos)
	if err != nil {
		return err
	}
	v, err := register(c, f, dsn)
	if err != nil {
		return fmt.Errorf("the guard is installed but the engine config was not written (run init again with --rotate-password): %w", err)
	}
	fmt.Fprintf(c.stderr, "basalt: credential %s; engine config %s\n", f.credFile, f.configPath)
	fmt.Fprint(c.stderr, f.vault.line(v))
	if f.rotated {
		fmt.Fprintf(c.stderr, "basalt: the agent's password changed; restart the engine so it uses the new one:\n  %s\n",
			cmds.Foreground().EngineRestart())
	}
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
func register(c *cliIO, f initFlags, dsn string) (config.VaultWritten, error) {
	if err := writeCredential(f.credFile, dsn, f.keepCredential); err != nil {
		return config.VaultWritten{}, err
	}
	return config.UpsertAgentVault(f.configPath, engineSettings(f, c.goos), config.Agent{
		Name: f.agent, OSUser: f.osUser, CredentialFile: f.credFile, InitArgs: f.initArgs,
	})
}

// writeCredential writes the agent's connection string, unless the role
// kept its password: then the file the engine reads stays, and must exist.
func writeCredential(path, dsn string, keep bool) error {
	if !keep {
		return config.WriteFile(path, []byte(dsn+"\n"))
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("the agent's role keeps its password but its credential file %s is missing; run init with --rotate-password", path)
	}
	return nil
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
	// vault is the config's vault the person chose (config.VaultOn or
	// VaultOff); vaultDefault applies only when the config has none. Both
	// "" keep the config's.
	vault, vaultDefault string
	// report, when set, is told the vault the install wrote.
	report func(config.VaultWritten)
	// initArgs are saved to the agent's config entry.
	initArgs []string
	// keepCredential leaves the credential file as it is (the role kept its
	// password); dsn is empty.
	keepCredential bool
	// personUIDs are added to the config's personUids.
	personUIDs []uint32
	// operatedBy replaces the config's operatedBy when set (PERSON or AGENT).
	operatedBy string
}

// agentServiceSpec is the service install spec with the agent's files in
// the service's own directories: the engine config (the existing one with
// the agent upserted) and the credential, both owned by the engine's user.
// For a plan that is only printed, contents are left out.
func agentServiceSpec(goos, bin, configPath, engineUser string, a agentInstall, printOnly bool) (service.Spec, error) {
	spec := service.Spec{GOOS: goos, Binary: bin, ConfigPath: configPath, User: engineUser}
	cred := filepath.Join(filepath.Dir(configPath), "agents", a.name+".url")
	spec.Files = []service.File{{Path: configPath}}
	if !a.keepCredential {
		spec.Files = append(spec.Files, service.File{Path: cred})
	}
	if printOnly {
		return spec, nil
	}
	// Root reads the existing config from the engine user's directory.
	open := func(p string) (*os.File, error) { return openEngineFile(p, engineUser) }
	raw, v, err := config.UpsertedVault(configPath, open,
		config.Settings{SocketDir: config.DefaultSocketDir(goos), PagesURL: a.pagesURL, Mode: config.ModeService, PersonUIDs: a.personUIDs,
			Vault: a.vault, VaultDefault: a.vaultDefault, OperatedBy: a.operatedBy},
		config.Agent{Name: a.name, OSUser: a.osUser, CredentialFile: cred, InitArgs: a.initArgs})
	if err != nil {
		return spec, err
	}
	if a.report != nil {
		a.report(v)
	}
	spec.Files[0].Content = raw
	// The unit's memory limits follow the config's pii.maxMemoryMB.
	var written config.Config
	if err := json.Unmarshal(raw, &written); err == nil {
		spec.MemoryMB = written.PIIOrDefault().MaxMemoryMB
	}
	if !a.keepCredential {
		spec.Files[1].Content = []byte(a.dsn + "\n")
	}
	return spec, nil
}

// vaultChoice is the init choice a service install carries: only basalt
// init, which is person-operated, runs it.
func (a agentInstall) vaultChoice() vaultChoice {
	return vaultChoice{given: modeOf(a.vault), def: modeOf(a.vaultDefault), why: personDefaultWhy}
}

// agentInstall is what `service install --agent` needs for this init.
func (f initFlags) agentInstall(dsn string) agentInstall {
	return agentInstall{name: f.agent, osUser: f.osUser, pagesURL: f.passkeyOrigin, dsn: dsn,
		vault: f.vault.given.enum(), vaultDefault: f.vault.def.enum(),
		initArgs: f.initArgs, keepCredential: f.keepCredential, personUIDs: f.personUIDs, operatedBy: f.operatedBy.settingOf(f.operatedByGiven)}
}

// serviceInstallArgs is the one command init runs under sudo. The
// credential goes on its stdin, never on the command line; when the role
// kept its password the credential file stays and nothing goes on stdin.
func serviceInstallArgs(f initFlags, bin string) []string {
	args := []string{bin, "service", "install", "--config", f.configPath, "--user", f.engineUser,
		"--agent", f.agent, "--os-user", f.osUser}
	if f.passkeyOrigin != "" {
		args = append(args, "--pages-url", f.passkeyOrigin)
	}
	// --vault only when the person gave it; else the default, which the
	// install applies only when the config has no vault yet.
	switch {
	case f.vault.given != "":
		args = append(args, "--"+flagVault+"="+string(f.vault.given))
	case f.vault.def != "":
		args = append(args, "--"+flagVaultDefault+"="+string(f.vault.def))
	}
	if f.operatedByGiven {
		args = append(args, "--operated-by", string(f.operatedBy))
	}
	for _, a := range f.initArgs {
		args = append(args, "--"+flagInitArg, a)
	}
	for _, uid := range f.personUIDs {
		args = append(args, "--"+flagPersonUID, strconv.FormatUint(uint64(uid), 10))
	}
	if f.keepCredential {
		return append(args, "--"+flagKeepCredential)
	}
	return append(args, "--credential-stdin")
}

// Flags of basalt service install --agent that carry init's saved flags and
// say the credential file stays.
const (
	flagInitArg        = "init-arg"
	flagKeepCredential = "keep-credential"
	flagPersonUID      = "person-uid"
)

// installService installs the engine service with the agent in one
// elevation, then checks the engine answers on the agent's socket.
func installService(c *cliIO, f initFlags, dsn string) error {
	uids, err := persons(c, f)
	if err != nil {
		return err
	}
	f.personUIDs = uids
	warnAgentIsPerson(c, f)
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
	bin, err := checkedExecutable(c)
	if err != nil {
		return err
	}
	if c.host.Euid() == 0 {
		return applyServiceInstall(c, bin, f.configPath, f.engineUser,
			f.agentInstall(dsn), false)
	}
	fmt.Fprintln(c.stderr, "basalt: installing the engine service with sudo:")
	return c.host.Sudo(c.ctx, serviceInstallArgs(f, bin), dsn+"\n", c.stderr, c.stderr)
}

// checkedExecutable is this basalt binary, refused (as the person, with
// lstat only) when anyone but root could change it: init hands it to sudo,
// so a binary the agent replaced would otherwise run as root.
func checkedExecutable(c *cliIO) (string, error) {
	bin, err := c.host.Executable()
	if err != nil {
		return "", err
	}
	if err := c.host.System(c.stderr, c.stderr).CheckBinary(bin); err != nil {
		return "", fmt.Errorf("%w (or run basalt init with --no-service)", err)
	}
	return bin, nil
}

// mayInstallService reports whether this init can go on to install the
// engine service (or print its plan): then the binary is checked before
// anything else, so a refusal leaves the database as it was.
func mayInstallService(c *cliIO, f initFlags) bool {
	return !f.noService && !f.pathsGiven && (f.yes || f.dryRun || c.interactive)
}

// applyServiceInstall builds and runs (or only prints) the service install
// with an agent. basalt service install runs it under sudo; init runs it
// itself when already root.
func applyServiceInstall(c *cliIO, bin, configPath, engineUser string, a agentInstall, printOnly bool) error {
	if !printOnly {
		a.report = func(v config.VaultWritten) { fmt.Fprint(c.stderr, a.vaultChoice().line(v)) }
	}
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

// envSudoUID is the uid of the user who ran sudo.
const envSudoUID = "SUDO_UID"

// persons are the uids the engine's person socket admits (CONTRACT.md, CLI,
// Recording the person): --person-uid, else the person running init (the
// user who ran sudo when init runs as root). Never root: without a person
// the service is not installed.
func persons(c *cliIO, f initFlags) ([]uint32, error) {
	uids := f.personUIDs
	if len(uids) == 0 {
		uid, err := invokingUID(c)
		if err != nil {
			return nil, err
		}
		uids = []uint32{uid}
	}
	if err := checkPersons(uids); err != nil {
		return nil, err
	}
	return uids, nil
}

// invokingUID is the uid of the person running init.
func invokingUID(c *cliIO) (uint32, error) {
	euid := c.host.Euid()
	if euid != 0 {
		return uint32(euid), nil
	}
	sudo := c.getenv(envSudoUID)
	if sudo == "" {
		return 0, errNoPerson
	}
	return parseUID(sudo)
}

var errNoPerson = errors.New("no person to admit on the engine's person socket (init runs as root without SUDO_UID); " +
	"give --person-uid N, the OS user id that runs basalt log, approve and revert")

// checkPersons refuses no uid and root.
func checkPersons(uids []uint32) error {
	if len(uids) == 0 {
		return errNoPerson
	}
	for _, u := range uids {
		if u == 0 {
			return errors.New("--person-uid 0 is root; give the OS user id of the person who runs basalt log, approve and revert")
		}
	}
	return nil
}

// parseUID reads an OS user id.
func parseUID(v string) (uint32, error) {
	uid, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not an OS user id", v)
	}
	return uint32(uid), nil
}

// warnAgentIsPerson says when the agent runs as a recorded person: the
// engine cannot tell two processes of one OS user apart, so that agent can
// reach the person socket too. Approve and revert still need the passkey.
func warnAgentIsPerson(c *cliIO, f initFlags) {
	u, err := user.Lookup(f.osUser)
	if err != nil {
		return // the service install reports an unknown OS user
	}
	for _, uid := range f.personUIDs {
		if strconv.FormatUint(uint64(uid), 10) == u.Uid {
			fmt.Fprintf(c.stderr, "basalt: warning: the agent runs as OS user %s, which is also the person the engine admits on its person socket. "+
				"While they share that user, basalt log, approve and revert over the socket see only this agent's ledger (the engine cannot tell you and the agent apart), "+
				"and the agent can use them too (approve and revert still need your passkey). For full isolation, run the agent as its own OS user: basalt init --os-user <user>\n", f.osUser)
			return
		}
	}
}
