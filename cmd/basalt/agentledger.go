package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// engineAccess is how the CLI tells service mode from same-user mode (owner
// decision SM-3): the installed service unit, which the person can read.
type engineAccess struct {
	// unitInstalled reports whether the engine service's unit is
	// installed.
	unitInstalled func() bool
}

// osEngineAccess looks for the systemd unit or the launchd plist on goos.
func osEngineAccess(goos string) engineAccess {
	unit := service.SystemdUnitPath
	if goos == goosDarwin {
		unit = service.LaunchdPlist
	}
	return engineAccess{
		unitInstalled: func() bool {
			_, err := os.Stat(unit)
			return err == nil
		},
	}
}

// goosDarwin is macOS's GOOS.
const goosDarwin = "darwin"

// agentLedger is the agent's ledger for basalt passkey: a
// direct connection with the agent's credential.
type agentLedger struct {
	person.Ledger
	// pinKey names the database and role for the log's ledger pin.
	pinKey            string
	agent, configPath string
	// role is the credential's database role in same-user mode.
	role  string
	close func()
}

// openLedger opens the agent's ledger with the agent's credential
// (agentURL). A person (not root) on a service engine cannot read it and is
// told to use sudo.
func openLedger(c *cliIO, agent, configPath string) (*agentLedger, error) {
	credFile := c.paths.credFile
	if c.needsAgent(agent, credFile) {
		// --agent is needed only when the engine serves more than one.
		if names, err := c.configuredAgents(configPath); err == nil && len(names) == 1 {
			agent = names[0]
		}
	}
	if c.serviceMode(agent, credFile, configPath) {
		return nil, errServiceFiles()
	}
	dsn, err := agentURL(c, agent, credFile, configPath)
	if err != nil {
		return nil, err
	}
	conn, err := connect(c.ctx, dsn)
	if err != nil {
		return nil, err
	}
	cfg := conn.Config()
	return &agentLedger{
		Ledger:     person.NewDBLedger(conn, c.now),
		pinKey:     fmt.Sprintf("%s\x00%d\x00%s\x00%s", cfg.Host, cfg.Port, cfg.Database, cfg.User),
		agent:      agent,
		role:       cfg.User,
		configPath: configPath,
		close:      func() { _ = conn.Close(context.WithoutCancel(c.ctx)) },
	}, nil
}

// serviceMode reports whether this command would read a service engine's
// files as a person (not root), which it cannot.
func (c *cliIO) serviceMode(agent, credFile, configPath string) bool {
	return c.host.Euid() != 0 && agent != "" && credFile == "" && c.getenv(envAgentURL) == "" &&
		configPath == c.systemConfig() && c.engine.unitInstalled()
}

// errServiceFiles is the answer of a command that would read a service
// engine's files without root: they are the engine's own, and the person
// socket that once answered for them is gone (CONTRACT.md, CLI, Removed).
func errServiceFiles() error {
	return errors.New("this engine runs as a service, so its config and credentials are the engine's own: run this command with sudo")
}

// pagesBase is the pages base URL links use: --pages-url, else the
// config's pagesUrl, else the local pages.
func (l *agentLedger) pagesBase(c *cliIO, flag string) string {
	if flag != "" {
		return flag
	}
	return configuredBase(c, "", l.agent, l.configPath)
}

// needsAgent reports whether nothing names the agent: no --agent, no
// credential given and no BASALT_DATABASE_URL.
func (c *cliIO) needsAgent(agent, credFile string) bool {
	return agent == "" && credFile == "" && c.paths.credFile == "" && c.getenv(envAgentURL) == ""
}

// configuredAgents are the agents this person can name: in service mode
// the agent sockets in the engine's socket directory (the person cannot
// read engine.json, but can list that directory), else the agents of the
// engine config.
func (c *cliIO) configuredAgents(configPath string) ([]string, error) {
	if configPath == c.systemConfig() && c.engine.unitInstalled() {
		entries, err := os.ReadDir(config.DefaultSocketDir(c.goos))
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range entries {
			name, ok := strings.CutSuffix(e.Name(), ".sock")
			if ok && e.Type()&os.ModeSocket != 0 && config.ValidAgentName(name) {
				names = append(names, name)
			}
		}
		return names, nil
	}
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		names = append(names, a.Name)
	}
	return names, nil
}
