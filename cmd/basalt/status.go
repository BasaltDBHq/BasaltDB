package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
// report for the person, plus where the engine runs. Never a secret, a
// file's contents or the credential file's path.

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
}

type engineOut struct {
	Reachable bool   `json:"reachable"`
	Build     string `json:"build,omitempty"`
	PID       int    `json:"pid,omitempty"`
	OSUser    string `json:"osUser,omitempty"`
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
	out, err := readStatus(c, *name, *configPath)
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
	cfg, err := config.Load(abs)
	if err != nil {
		return statusOut{}, err
	}
	a, err := statusAgent(cfg, name, abs)
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
	dsn, err := config.ReadCredential(a.CredentialFile)
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
		Name: a.Name, Commands: cmds, OperatedBy: cfg.OperatedBy, Setup: a.Setup,
		PagesBase: base, PagesOrigin: servedPages(c, cfg, eng.Reachable), EngineRunning: eng.Reachable,
		Probe:    agent.DBProbe{Q: pool, Migrations: guard.Migrations()},
		Passkeys: func(ctx context.Context) ([]passkey.Credential, error) { return ledger.Passkeys(ctx, pool) },
		Log:      slog.New(slog.DiscardHandler), Now: c.now,
	}.Report(c.ctx)
	if err != nil {
		return statusOut{}, err
	}
	eng.Build = r.Engine.Build
	return statusOut{StatusReport: r, Engine: eng, ConfigPath: abs, SocketDir: cfg.SocketDir, StateDir: cfg.StateDirFor(c.goos)}, nil
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
// pid, owned by its OS user. No lock file: not running.
func runningEngine(socketDir string) engineOut {
	path := engine.LockPath(socketDir)
	if _, err := os.Stat(path); err != nil {
		return engineOut{}
	}
	pid, running, err := server.Running(path)
	if err != nil || !running {
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

// printStatus is basalt status for the person.
func printStatus(w io.Writer, s statusOut) {
	engineLine := "not running"
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
	if v := s.Vault; v != nil {
		fmt.Fprintf(w, "Vault:        %s%s\n", v.State, fingerprintWords(v.Fingerprint))
	}
	ready := "ready"
	if !s.Ready {
		ready = "not ready"
	}
	fmt.Fprintf(w, "\nAgent %s: %s\n", s.Agent, ready)
	fmt.Fprintf(w, "  Guard:      %s\n", guardWords(s.Guard))
	fmt.Fprintf(w, "  Passkeys:   %s\n", passkeyWords(s.Passkeys))
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
		for _, st := range p.NextSteps {
			switch {
			case st.Command != "":
				fmt.Fprintf(w, "      Run: %s\n", st.Command)
			case st.URL != "":
				fmt.Fprintf(w, "      Open: %s\n", st.URL)
			}
		}
	}
}

func fingerprintWords(fp string) string {
	if fp == "" {
		return ""
	}
	return ", engine " + fp
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
