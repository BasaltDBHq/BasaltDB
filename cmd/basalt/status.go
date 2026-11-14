package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// basalt status (CONTRACT.md, CLI; owner decision AE-13): the status tool's
// report for the person, plus where the engine runs. Never a secret or a
// file's contents. The credential file's path appears only as a saved
// --credential-file flag in an init command (AE-15).

// statusOut is basalt status --json: the status tool's result plus
// configPath, engine.pid, engine.osUser, socketDir and stateDir.
type statusOut struct {
	agent.StatusReport
	// Engine replaces the report's engine (encoding/json takes the
	// shallower field) to add the pid and OS user.
	Engine     engineOut `json:"engine"`
	ConfigPath string    `json:"configPath"`
	SocketDir  string    `json:"socketDir"`
	StateDir   string    `json:"stateDir"`
	// vaultID is the engine id in same-user mode when the Vault is on:
	// the connection state only the running engine knows is left out of
	// the report, and the text output still shows the id (localVault).
	vaultID *agent.VaultStatus
}

type engineOut struct {
	Reachable bool   `json:"reachable"`
	Build     string `json:"build,omitempty"`
	PID       int    `json:"pid,omitempty"`
	OSUser    string `json:"osUser,omitempty"`
	// Unknown is a lock file this user cannot open: whether the engine
	// runs cannot be told (reachable is false, with no problem for it).
	Unknown bool `json:"unknown,omitempty"`
	// why says why it is unknown, for the text output.
	why string
}

// statusAgentPool bounds basalt status's connections: one at a time.
const statusAgentPool = 1

func runStatus(c *cliIO, args []string) int {
	fs := c.flags("status")
	name := fs.String("agent", "", "the agent (default: the config's only agent)")
	configPath := fs.String("config", config.DefaultPath(c.goos), "engine config file")
	asJSON := fs.Bool("json", false, "print the status tool's result, with where the engine runs, as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	if *name != "" && !config.ValidAgentName(*name) {
		return c.fail(fmt.Errorf("%w: agent name %q is not valid", errUsage, *name))
	}
	out, err := readStatus(c, *name, configOrFallback(c.host, fs, *configPath))
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return exitCode(c, enc.Encode(out))
	}
	printStatus(c.stdout, out)
	return exitOK
}

// configOrFallback is the config a person command reads: the --config value,
// or, when --config was not given, perUserConfigFallback of the default.
func configOrFallback(h host, fs *flag.FlagSet, path string) string {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "config" })
	if given {
		return path
	}
	return perUserConfigFallback(h, path)
}

// perUserConfigFallback is the config a command reads when --config is not
// given: the system path, unless this is not root, nothing is installed
// there, and init left a config in the user's own config directory.
func perUserConfigFallback(h host, system string) string {
	if h.Euid() == 0 {
		return system
	}
	if _, err := os.Stat(system); !errors.Is(err, fs.ErrNotExist) {
		return system
	}
	base, err := h.UserConfigDir()
	if err != nil {
		return system
	}
	user := filepath.Join(base, perUserDirName, "engine.json")
	if _, err := os.Stat(user); err != nil {
		return system
	}
	return user
}

// readStatus asks the engine over the person socket in service mode, else
// reads the config and the agent's database itself.
func readStatus(c *cliIO, name, configPath string) (statusOut, error) {
	if c.serviceMode(name, "", configPath) {
		return serviceStatus(c, name)
	}
	if name == "" && configPath == config.DefaultPath(c.goos) && c.engine.unitInstalled() {
		return statusOut{}, fmt.Errorf("%w: the engine runs as a service, so give --agent NAME (the engine's files are its own)", errUsage)
	}
	return localStatus(c, name, configPath)
}

// personStatus is STATUS: the status tool's report and where the engine runs.
func personStatus(c *cliIO, name string) (agent.StatusReport, person.StatusDTO, error) {
	dto, err := person.Client{Path: c.engine.personSocket}.Status(c.ctx, name)
	if err != nil {
		return agent.StatusReport{}, person.StatusDTO{}, personError(c, name, err)
	}
	var r agent.StatusReport
	if err := json.Unmarshal(dto.Status, &r); err != nil {
		return agent.StatusReport{}, person.StatusDTO{}, fmt.Errorf("the engine's status cannot be read: %w", err)
	}
	return r, dto, nil
}

func serviceStatus(c *cliIO, name string) (statusOut, error) {
	r, dto, err := personStatus(c, name)
	if err != nil {
		return statusOut{}, err
	}
	return statusOut{
		StatusReport: r,
		Engine:       engineOut{Reachable: r.Engine.Reachable, Build: r.Engine.Build, PID: dto.Engine.PID, OSUser: dto.Engine.OSUser},
		ConfigPath:   config.DefaultPath(c.goos),
		SocketDir:    dto.SocketDir,
		StateDir:     dto.StateDir,
	}, nil
}

// localStatus is the status of an engine the CLI can read the files of:
// the config, the agent's credential, the engine's lock file.
func localStatus(c *cliIO, name, configPath string) (statusOut, error) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return statusOut{}, err
	}
	cfg, err := loadEngineConfig(c, abs)
	if err != nil {
		return statusOut{}, err
	}
	a, err := statusAgent(cfg.Config, name, abs)
	if err != nil {
		return statusOut{}, err
	}
	cmds, err := agent.NewCommands(a.Name, abs, c.goos, a.InitArgs)
	if err != nil {
		return statusOut{}, err
	}
	if !cfg.Service() {
		cmds = cmds.Foreground()
	}
	dsn, err := cfg.credential(a.CredentialFile)
	if err != nil {
		return statusOut{}, fmt.Errorf("the credential of agent %s cannot be read: %w", a.Name, withoutPath(err))
	}
	pool, err := agentdb.NewPool(c.ctx, dsn, statusAgentPool)
	if err != nil {
		return statusOut{}, err
	}
	defer pool.Close()
	eng := runningEngine(cfg.SocketDir)
	base, err := cfg.PagesBase()
	if err != nil {
		return statusOut{}, err
	}
	r, err := agent.LocalStatus{
		Name: a.Name, Commands: cmds, OperatedBy: cfg.OperatedBy, DevLocalPages: cfg.DevLocalPages, Setup: a.Setup,
		PagesBase: base, PagesOrigin: servedPages(c, cfg.Config, eng.Reachable), EngineRunning: eng.Reachable, EngineUnknown: eng.Unknown,
		Probe: agent.DBProbe{
			Q: pool, Migrations: guard.Migrations(),
			Kept: engine.KeptSetAside(chainpin.File{Dir: cfg.StateDirFor(c.goos)}, a.Name, slog.New(slog.DiscardHandler)),
		},
		Passkeys: func(ctx context.Context) ([]passkey.Credential, error) { return ledger.Passkeys(ctx, pool) },
		Log:      slog.New(slog.DiscardHandler), Now: c.now,
	}.Report(c.ctx)
	if err != nil {
		return statusOut{}, err
	}
	eng.Build = r.Engine.Build
	stateDir := cfg.StateDirFor(c.goos)
	out := statusOut{StatusReport: r, Engine: eng, ConfigPath: abs, SocketDir: cfg.SocketDir, StateDir: stateDir}
	if !eng.Unknown {
		out.Vault, out.vaultID = localVault(cfg.Config, stateDir)
	}
	return out, nil
}

// statusAgent is the named agent, or the config's only one.
func statusAgent(cfg config.Config, name, path string) (config.Agent, error) {
	names := make([]string, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		if a.Name == name || (name == "" && len(cfg.Agents) == 1) {
			return a, nil
		}
		names = append(names, a.Name)
	}
	if name == "" {
		return config.Agent{}, fmt.Errorf("%w: %s has agents %s; give --agent NAME", errUsage, path, strings.Join(names, ", "))
	}
	return config.Agent{}, fmt.Errorf("agent %q is not in %s; run basalt init --agent %s", name, path, name)
}

// runningEngine reads the engine's lock file: held while it runs, with its
// pid, owned by its OS user. No lock file: not running. A lock file this
// user cannot open read-write (another user's engine): unknown, never "not
// running". Probing takes the lock for an instant when it is free, so an
// engine starting in that instant fails with "already running" and must be
// started again; status never holds it longer than the probe.
func runningEngine(socketDir string) engineOut {
	path := engine.LockPath(socketDir)
	if _, err := os.Stat(path); err != nil {
		return engineOut{}
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return engineOut{Unknown: true, OSUser: fileOwner(path), why: withoutPath(err).Error()}
	}
	_ = f.Close()
	pid, running, err := server.Running(path)
	switch {
	case err != nil:
		return engineOut{Unknown: true, OSUser: fileOwner(path), why: withoutPath(err).Error()}
	case !running:
		return engineOut{}
	}
	return engineOut{Reachable: true, PID: pid, OSUser: fileOwner(path)}
}

// servedPages is the origin of the local pages when the running engine
// serves them, else "".
func servedPages(c *cliIO, cfg config.Config, running bool) string {
	p, err := cfg.Pages()
	if !running || err != nil || p.Addr == "" || !c.host.PagesUp(c.ctx, p.Origin) {
		return ""
	}
	return p.Origin
}

// withoutPath drops the file name from an OS error: basalt status never
// names the credential file.
func withoutPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// printStatus is basalt status for the person. The report carries text
// from the engine and the database, so the whole of it is escaped
// (terminalText).
func printStatus(w io.Writer, s statusOut) {
	var b strings.Builder
	writeStatus(&b, s)
	fmt.Fprint(w, terminalText(b.String()))
}

func writeStatus(w io.Writer, s statusOut) {
	engineLine := "not running"
	if s.Engine.Unknown {
		engineLine = fmt.Sprintf("unknown (its lock file, owned by %s, cannot be opened: %s)", s.Engine.OSUser, s.Engine.why)
	}
	if s.Engine.Reachable {
		engineLine = "running"
		if s.Engine.PID > 0 {
			engineLine += fmt.Sprintf(" (pid %d, OS user %s)", s.Engine.PID, s.Engine.OSUser)
		}
	}
	pages := s.Pages.URL + " (not served by the engine)"
	if s.Pages.Served {
		pages = s.Pages.URL + " (served by the engine)"
	}
	fmt.Fprintf(w, "Config:       %s\n", s.ConfigPath)
	fmt.Fprintf(w, "Engine:       %s, basalt %s\n", engineLine, s.Engine.Build)
	fmt.Fprintf(w, "Sockets:      %s\n", s.SocketDir)
	fmt.Fprintf(w, "State:        %s\n", s.StateDir)
	fmt.Fprintf(w, "Pages:        %s\n", pages)
	fmt.Fprintf(w, "Operated by:  %s (enforcement %s)\n", s.OperatedBy, s.Enforcement)
	switch {
	case s.Vault != nil:
		fmt.Fprintf(w, "Vault:        %s\n", vaultWords(*s.Vault, s.StateDir))
		if s.Vault.EngineID != "" {
			fmt.Fprintf(w, "Engine id:    %s\n", engineIDWords(*s.Vault))
		}
	case s.vaultID != nil:
		fmt.Fprintln(w, "Vault:        ON in the config; only the running engine knows whether it is connected (the agent's status tool reports it)")
		fmt.Fprintf(w, "Engine id:    %s\n", engineIDWords(*s.vaultID))
	}
	ready := "ready"
	if !s.Ready {
		ready = "not ready"
	}
	fmt.Fprintf(w, "\nAgent %s: %s\n", s.Agent, ready)
	fmt.Fprintf(w, "  Guard:      %s\n", guardWords(s.Guard))
	fmt.Fprintf(w, "  Passkeys:   %s\n", passkeyWords(s.Passkeys))
	if s.Ledger != nil {
		fmt.Fprintf(w, "  Ledger:     %s\n", ledgerWords(*s.Ledger))
	}
	if s.Setup.State != "NONE" {
		fmt.Fprintf(w, "  Setup:      %s %s code %s\n", s.Setup.State, s.Setup.Kind, s.Setup.SetupID)
	}
	if len(s.Problems) == 0 {
		return
	}
	fmt.Fprintln(w, "  Problems:")
	for _, p := range s.Problems {
		fmt.Fprintf(w, "    %s %s: %s\n", p.Severity, p.Code, p.Message)
		if p.PersonMessage != "" {
			fmt.Fprintf(w, "      %s\n", strings.ReplaceAll(p.PersonMessage, "\n", "\n      "))
		}
		// A command or link the person message already names is not
		// printed again.
		for _, st := range p.NextSteps {
			switch {
			case st.Command != "" && !strings.Contains(p.PersonMessage, st.Command):
				fmt.Fprintf(w, "      Run: %s\n", st.Command)
			case st.Command == "" && st.URL != "" && !strings.Contains(p.PersonMessage, st.URL):
				fmt.Fprintf(w, "      Open: %s\n", st.URL)
			}
		}
	}
}

// guardWords is the guard's version against the build's, in words.
func guardWords(g agent.GuardStatus) string {
	installed := "?"
	if g.Installed != nil {
		installed = fmt.Sprint(*g.Installed)
	}
	at := fmt.Sprintf("version %s, this basalt has %d: ", installed, g.Build)
	switch g.State {
	case guard.GuardOK:
		return at + "up to date"
	case guard.GuardUpgradeAvailable:
		return at + "upgrade available (missing " + joinInts(g.MissingNonBreaking) + ")"
	case guard.GuardOutdated:
		return at + "upgrade required (missing " + joinInts(g.MissingBreaking) + ")"
	case guard.GuardNewer:
		return at + "newer than this basalt"
	case guard.GuardMissing:
		return "not installed"
	}
	return "unknown (the database did not answer)"
}

// daysPerYear says 365 days of record retention as 1 year.
const daysPerYear = 365

// decimalScale rounds to one decimal.
const decimalScale = 10

func ledgerWords(l agent.LedgerStatus) string {
	return fmt.Sprintf("%s in basalt_meta; values kept %d days, records %s", byteWords(l.Bytes), l.ValuesKeptDays, keptWords(l.RecordsKeptDays))
}

func keptWords(days int) string {
	if days == daysPerYear {
		return "1 year"
	}
	return fmt.Sprintf("%d days", days)
}

// byteWords is n with one decimal in B, KB, MB or GB (powers of 1024).
func byteWords(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n) / unit
	for _, suffix := range []string{"KB", "MB"} {
		// Round first: 1048575 B is 1023.999 KB, which prints as 1.0 MB.
		if math.Round(v*decimalScale)/decimalScale < unit {
			return fmt.Sprintf("%.1f %s", v, suffix)
		}
		v /= unit
	}
	return fmt.Sprintf("%.1f GB", v)
}

func passkeyWords(p agent.PasskeysStatus) string {
	switch {
	case p.Active == nil:
		return "unknown"
	case *p.Active == 0:
		return "none registered"
	case *p.Active == 1:
		return "1 active"
	}
	return fmt.Sprintf("%d active", *p.Active)
}
