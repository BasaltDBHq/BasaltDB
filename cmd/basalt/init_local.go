package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/user"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
)

// setupWait bounds how long init waits for the engine's setup page after
// the service starts.
const (
	setupWait     = 30 * time.Second
	setupWaitStep = 250 * time.Millisecond
)

// runInitLocal is basalt init on a person-operated engine (CONTRACT.md,
// basalt init, persona 1). It only starts things: it installs the engine
// service through the system's administrator dialog when there is none
// yet, waits for the engine's setup page, then prints the setup link and
// opens it in the browser. The person does the rest on the page. It asks
// nothing in the terminal and never reads the admin connection string.
func runInitLocal(c *cliIO, args []string) int {
	job, err := parseInitLocal(c, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return c.fail(err)
	}
	if c.host.Euid() == 0 {
		return c.fail(fmt.Errorf("%w: run basalt init as your own OS user, not root: the agent runs as that user, and the setup page asks for your password when it needs one", errUsage))
	}
	if !job.Demo {
		return c.fail(fmt.Errorf("%w: the setup page offers only the sample database for now: run basalt init --demo", errUsage))
	}
	me, err := user.Current()
	if err != nil {
		return c.fail(fmt.Errorf("your OS user cannot be read: %w", err))
	}
	job.OSUser = me.Username
	if err := ensureEngineService(c); err != nil {
		return c.fail(err)
	}
	state, err := waitForSetupPage(c)
	if err != nil {
		return c.fail(err)
	}
	if state == engineSetUp {
		fmt.Fprintf(c.stderr, "basalt: the engine on this computer is already set up; changing it from the setup page is not available yet. The agent connects with:\n  basalt mcp --agent %s\n", job.Agent)
		return exitOK
	}
	link, err := localsetup.Link(engine.SetupOrigin, job)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stdout, link)
	fmt.Fprintln(c.stdout, "basalt mcp --agent "+job.Agent)
	if err := c.host.OpenURL(c.ctx, link); err != nil {
		fmt.Fprintln(c.stderr, "basalt: the browser did not open; open the link above by hand")
	}
	fmt.Fprintln(c.stderr, "basalt: finish the setup on the page that opened: type your database's admin connection string there, never here. The last line above is the MCP server the agent registers.")
	return exitOK
}

// parseInitLocal reads basalt init's flags on a person-operated engine:
// --agent and --demo only. Any other flag is a usage error.
func parseInitLocal(c *cliIO, args []string) (localsetup.Job, error) {
	fs := newFlagSet("init")
	fs.SetOutput(c.stderr)
	agent := fs.String("agent", "", "the agent's name (default: "+demo.Agent+" with --demo)")
	demoFlag := fs.Bool("demo", false, "set up the sample database")
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: basalt init [--agent NAME] [--demo]\n\nInstalls the engine service when needed, then prints and opens the setup link. Finish the setup on that page.")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return localsetup.Job{}, err
		}
		return localsetup.Job{}, fmt.Errorf("%w: basalt init on this computer takes only --agent and --demo; the setup page asks for the rest", errUsage)
	}
	if fs.NArg() > 0 {
		return localsetup.Job{}, fmt.Errorf("%w: basalt init takes no arguments", errUsage)
	}
	name := *agent
	if name == "" {
		name = demo.Agent
	}
	if !localsetup.ValidAgentName(name) {
		return localsetup.Job{}, fmt.Errorf("%w: --agent %q is not a name an agent can have (lowercase letters, digits and _)", errUsage, name)
	}
	return localsetup.Job{Job: localsetup.JobInstall, Agent: name, Demo: *demoFlag}, nil
}

// ensureEngineService installs the engine service through the system's
// administrator dialog when it is not installed yet: one password, in the
// dialog. It never falls back to running the engine as the person.
func ensureEngineService(c *cliIO) error {
	if c.host.System(io.Discard, io.Discard).Exists(service.UnitPath(c.goos)) {
		return nil
	}
	if err := c.host.DialogAvailable(c.goos); err != nil {
		return noDialog(err)
	}
	bin, script, err := dialogScript(c)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: asking for your password in the system's administrator dialog to install the engine service as %s; it runs:\n  %s\n",
		service.DefaultUser(c.goos), shellJoin(dialogEngineArgs(c.goos, bin)))
	if err := c.host.AdminDialog(c.ctx, c.goos, script, c.stderr); err != nil {
		if errors.Is(err, service.ErrNoDialog) {
			return noDialog(err)
		}
		return err
	}
	return nil
}

// engineState is what the engine's setup routes say about it.
type engineState int

const (
	engineWaiting engineState = iota // no config yet: the setup page installs
	engineSetUp                      // it has a config
)

// waitForSetupPage waits until the engine answers its setup routes, and
// reads from the answer whether it is waiting for its config.
func waitForSetupPage(c *cliIO) (engineState, error) {
	ctx, cancel := context.WithTimeout(c.ctx, setupWait)
	defer cancel()
	for {
		code, err := c.host.SetupState(ctx, engine.SetupOrigin)
		switch {
		case err == nil && code == localsetup.CodeJobUnavailable:
			return engineSetUp, nil
		case err == nil:
			return engineWaiting, nil
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("the engine service did not answer on %s within %s; see %s", engine.SetupOrigin, setupWait, engineLogHint(c.goos))
		case <-time.After(setupWaitStep):
		}
	}
}
