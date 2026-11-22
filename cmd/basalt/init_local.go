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
	switch state {
	case engineSetUp:
		return changeLink(c, job)
	case engineRemoved:
		return removeEngineService(c)
	case engineWaiting:
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

// changeLink is basalt init on an engine that is already set up: it prints
// and opens the setup page's CHANGE link for the agent, where the person
// picks Update or Remove (CONTRACT.md, The local setup page). It prints no
// basalt mcp line: the agent is registered already.
func changeLink(c *cliIO, job localsetup.Job) int {
	job.Job, job.Demo = localsetup.JobChange, false
	link, err := localsetup.Link(engine.SetupOrigin, job)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stdout, link)
	if err := c.host.OpenURL(c.ctx, link); err != nil {
		fmt.Fprintln(c.stderr, "basalt: the browser did not open; open the link above by hand")
	}
	fmt.Fprintln(c.stderr, "basalt: the engine on this computer is already set up. On the page that opened, update the guard or remove BasaltDB: type your database's admin connection string there, never here. After a Remove, run basalt init once more: it removes the engine service.")
	return exitOK
}

// removeEngineService removes the engine service after the setup page
// removed BasaltDB, through the administrator dialog with its fixed
// script (service.RemoveScript), which refuses while engine.json exists.
func removeEngineService(c *cliIO) int {
	if err := c.host.DialogAvailable(c.goos); err != nil {
		return c.fail(fmt.Errorf("BasaltDB is removed from the database, but the engine service is removed through the system's administrator dialog, which cannot be shown here (%w). Run basalt init again in a desktop session on this machine", err))
	}
	script, err := service.RemoveScript(c.goos)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "basalt: BasaltDB is removed from the database. Asking for your password in the system's administrator dialog to remove the engine service: it stops the service and removes its files and OS users.")
	if err := c.host.AdminDialog(c.ctx, c.goos, script, c.stderr); err != nil {
		if errors.Is(err, service.ErrDialogCancelled) {
			return c.fail(errors.New("the administrator dialog was closed, so the engine service stays. Run basalt init again to remove it"))
		}
		return c.fail(fmt.Errorf("the engine service was not removed: %w", err))
	}
	fmt.Fprintln(c.stderr, "basalt: the engine service is removed.")
	return exitOK
}

// parseInitLocal reads basalt init's flags on a person-operated engine:
// --agent and --demo only. Any other flag is a usage error.
func parseInitLocal(c *cliIO, args []string) (localsetup.Job, error) {
	fs := newFlagSet("init")
	fs.SetOutput(c.stderr)
	agent := fs.String("agent", "", "the agent's name (default: "+demo.Agent+")")
	demoFlag := fs.Bool("demo", false, "set up the sample database instead of your own tables")
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: basalt init [--agent NAME] [--demo]\n\n"+
			"Installs the engine service when needed, then prints and opens the setup link. Finish the setup on that page:\n"+
			"the admin connection string is typed there, never here. On a bot's machine, run basalt init --remote instead.\n\n"+manyAgentsHelp)
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
	engineRemoved                    // the page removed its last agent
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
		case err == nil && code == localsetup.CodeEngineRemoved:
			return engineRemoved, nil
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
