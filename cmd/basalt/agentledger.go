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
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// engineAccess is how the CLI tells service mode from same-user mode (owner
// decision SM-3): the installed service unit, which the person can read,
// and the engine's person socket.
type engineAccess struct {
	// unitInstalled reports whether the engine service's unit is
	// installed.
	unitInstalled func() bool
	// personSocket is the engine's person socket.
	personSocket string
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
		personSocket: config.PersonSocketPath(config.DefaultSocketDir(goos)),
	}
}

// goosDarwin is macOS's GOOS.
const goosDarwin = "darwin"

// agentLedger is the agent's ledger for basalt log, approve and revert:
// a direct connection with the agent's credential (same-user mode), or
// the engine's person socket (service mode).
type agentLedger struct {
	person.Ledger
	// pinKey names the database and role for the log's ledger pin.
	pinKey string
	// pages is the engine's answer to PAGES in service mode, nil in
	// same-user mode (the config says).
	pages             *person.PagesDTO
	agent, configPath string
	// role is the credential's database role in same-user mode.
	role  string
	close func()
}

// openLedger opens the agent's ledger. With the engine service installed,
// --agent, the default --config and no credential given, it goes through
// the person socket and never reads the engine's files; else it reads the
// credential as before (agentURL).
func openLedger(c *cliIO, agent, credFile, configPath string) (*agentLedger, error) {
	if c.serviceMode(agent, credFile, configPath) {
		return openPersonLedger(c, agent)
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

// serviceMode reports whether this command goes through the person socket.
func (c *cliIO) serviceMode(agent, credFile, configPath string) bool {
	return agent != "" && credFile == "" && c.getenv(envAgentURL) == "" &&
		configPath == config.DefaultPath(c.goos) && c.engine.unitInstalled()
}

// openPersonLedger asks the engine for its pages, which also tells whether
// it runs and admits this OS user, before any other call.
func openPersonLedger(c *cliIO, agent string) (*agentLedger, error) {
	client := person.Client{Path: c.engine.personSocket}
	pages, err := client.Pages(c.ctx)
	if err != nil {
		return nil, personError(c, agent, err)
	}
	return &agentLedger{
		Ledger: client.Agent(agent),
		pinKey: "person\x00" + c.engine.personSocket + "\x00" + agent,
		pages:  &pages,
		agent:  agent,
		close:  func() {},
	}, nil
}

// personError says what to do when the person socket does not answer:
// never the OS error (permission denied), never a fallback to the files.
func personError(c *cliIO, agent string, err error) error {
	uid := os.Getuid()
	switch {
	case errors.Is(err, person.ErrNotRunning):
		return fmt.Errorf("the engine is not running; start it with %s, then run this command again", service.StartCommand(c.goos))
	case errors.Is(err, person.ErrUIDNotAllowed):
		return fmt.Errorf("the engine does not let OS user %d use its person socket; add it with sudo basalt init --agent %s --person-uid %d",
			uid, agent, uid)
	}
	return err
}

// pagesBase is the pages base URL links use: --pages-url, else the
// engine's (service mode) or the config's pagesUrl, else the local pages.
func (l *agentLedger) pagesBase(c *cliIO, flag string) string {
	switch {
	case flag != "":
		return flag
	case l.pages == nil:
		return configuredBase(c, "", l.agent, l.configPath)
	case l.pages.PagesURL == "":
		return links.DefaultLocal
	}
	return l.pages.PagesURL
}

// localPages is the origin of the pages the engine serves when it answers
// there, else "" (see localPages).
func (l *agentLedger) localPages(c *cliIO, flag string) string {
	switch {
	case l.pages == nil:
		return localPages(c, flag, l.agent, l.configPath)
	case flag != "" || l.pages.LocalOrigin == "" || !c.host.PagesUp(c.ctx, l.pages.LocalOrigin):
		return ""
	}
	return l.pages.LocalOrigin
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
