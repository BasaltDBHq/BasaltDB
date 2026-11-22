package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
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

// agentLedger is the agent's ledger for basalt approve and passkey: a
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
func openLedger(c *cliIO, agent, credFile, configPath string) (*agentLedger, error) {
	credFile = cmp.Or(credFile, c.paths.credFile)
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

// localPages is the origin of the pages the engine serves when it answers
// there, else "" (see localPages).
func (l *agentLedger) localPages(c *cliIO, flag string) string {
	return localPages(c, flag, l.agent, l.configPath)
}

// credentials are the active passkeys' credentials, to fill credentialIds
// and check a code before relaying it.
func (l *agentLedger) credentials(ctx context.Context) ([]passkey.Credential, error) {
	keys, err := l.ListPasskeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]passkey.Credential, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Credential)
	}
	return out, nil
}

// ownAgent is the agent's name: the one given, else the one in the role of
// the credential (<prefix>_agent_<name>), "" when it cannot be told.
func (l *agentLedger) ownAgent() string {
	if l.agent != "" {
		return l.agent
	}
	i := strings.Index(l.role, "_agent_")
	if i < 0 {
		return ""
	}
	return l.role[i+len("_agent_"):]
}
