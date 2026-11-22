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
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
)

// setupWait bounds how long init waits for the engine's setup page after
// the service starts.
const (
	setupWait     = 30 * time.Second
	setupWaitStep = 250 * time.Millisecond
	// removalWait is how long init waits, after it opened the Update/Remove
	// link, for the page's Remove: as long as an approval wait.
	removalWait     = agent.DefaultApprovalWait
	removalWaitStep = 500 * time.Millisecond
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
		if code, reset := changeLink(c, job); !reset {
			return code
		}
		// The person answered "No, this isn't mine" and reset the engine
		// through the administrator dialog (Not your database): once it
		// waits for a first install, this init goes on to the install link.
		next, err := waitForSetupPage(c)
		if err != nil {
			return c.fail(err)
		}
		if next != engineWaiting {
			return c.fail(errors.New("the engine was set up again before this init could open the install page; run basalt init again"))
		}
	case engineRemoved:
		return removeEngineService(c)
	case engineWaiting, engineResetAsked:
		// engineResetAsked is never the answer here: waitForSetupPage
		// takes a "No" it finds at the start as an engine set up.
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
// basalt mcp line: the agent is registered already. reset: the person
// answered "No, this isn't mine" on the page and reset the engine through
// the administrator dialog (Not your database), and init goes on to the
// install.
func changeLink(c *cliIO, job localsetup.Job) (code int, reset bool) {
	job.Job, job.Demo = localsetup.JobChange, false
	link, err := localsetup.Link(engine.SetupOrigin, job)
	if err != nil {
		return c.fail(err), false
	}
	fmt.Fprintln(c.stdout, link)
	if err := c.host.OpenURL(c.ctx, link); err != nil {
		fmt.Fprintln(c.stderr, "basalt: the browser did not open; open the link above by hand")
	}
	fmt.Fprintln(c.stderr, "basalt: the engine on this computer is already set up. On the page that opened, update the guard or remove BasaltDB: type your database's admin connection string there, never here.")
	switch waitForRemoval(c) {
	case engineRemoved:
		return removeEngineService(c), false
	case engineResetAsked:
		if code := resetEngineService(c); code != exitOK {
			return code, false
		}
		return exitOK, true
	case engineWaiting, engineSetUp:
	}
	fmt.Fprintln(c.stderr, "basalt: after a Remove on that page, run basalt init once more: it removes the engine service.")
	return exitOK, false
}

// waitForRemoval asks the engine, for up to removalWait (as long as an
// approval wait), whether the page's Remove deleted engine.json
// (ENGINE_REMOVED, engineRemoved) or the person answered "No, this isn't
// mine" (RESET_ASKED, engineResetAsked). Any other answer, an Update
// included, keeps waiting until the time is up (engineSetUp).
func waitForRemoval(c *cliIO) engineState {
	ctx, cancel := context.WithTimeout(c.ctx, removalWait)
	defer cancel()
	for {
		code, err := c.host.SetupState(ctx, engine.SetupOrigin)
		switch {
		case err == nil && code == localsetup.CodeEngineRemoved:
			return engineRemoved
		case err == nil && code == localsetup.CodeResetAsked:
			return engineResetAsked
		}
		select {
		case <-ctx.Done():
			return engineSetUp
		case <-time.After(removalWaitStep):
		}
	}
}

// resetEngineService resets BasaltDB on this computer after the person
// answered "No, this isn't mine" on the setup page, through the
// administrator dialog with its fixed script (service.ResetScript): it
// deletes the engine's config, credentials and pins and restarts the
// service. The person's password is the proof the page cannot give.
func resetEngineService(c *cliIO) int {
	return runServiceDialog(c, serviceDialog{
		script:    service.ResetScript,
		noDialog:  "BasaltDB on this computer is reset through the system's administrator dialog, which cannot be shown here (%w), so nothing was reset. Run basalt init again in a desktop session on this machine",
		asking:    "basalt: you answered that the database this computer's BasaltDB serves is not yours. Asking for your password in the system's administrator dialog to reset BasaltDB on this computer: it deletes the engine's config, its agents' credentials and its certificate pins, and restarts the engine. No database is touched.",
		cancelled: "the administrator dialog was closed, so nothing was reset. Run basalt init again and answer the question on the page again",
		failed:    "BasaltDB on this computer was not reset: %w",
		done:      "basalt: BasaltDB on this computer is reset; nothing changed in any database. Opening the setup page for your own database.",
	})
}

// removeEngineService removes the engine service after the setup page
// removed BasaltDB, through the administrator dialog with its fixed
// script (service.RemoveScript), which refuses while engine.json exists.
func removeEngineService(c *cliIO) int {
	return runServiceDialog(c, serviceDialog{
		script:    service.RemoveScript,
		noDialog:  "BasaltDB is removed from the database, but the engine service is removed through the system's administrator dialog, which cannot be shown here (%w). Run basalt init again in a desktop session on this machine",
		asking:    "basalt: BasaltDB is removed from the database. Asking for your password in the system's administrator dialog to remove the engine service: it stops the service and removes its files and OS users.",
		cancelled: "the administrator dialog was closed, so the engine service stays. Run basalt init again to remove it",
		failed:    "the engine service was not removed: %w",
		done:      "basalt: the engine service is removed.",
	})
}

// serviceDialog is one fixed script run through the administrator dialog,
// with what init says around it.
type serviceDialog struct {
	script                                    func(goos string) (string, error)
	noDialog, asking, cancelled, failed, done string
}

func runServiceDialog(c *cliIO, d serviceDialog) int {
	if err := c.host.DialogAvailable(c.goos); err != nil {
		return c.fail(fmt.Errorf(d.noDialog, err))
	}
	script, err := d.script(c.goos)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, d.asking)
	if err := c.host.AdminDialog(c.ctx, c.goos, script, c.stderr); err != nil {
		if errors.Is(err, service.ErrDialogCancelled) {
			return c.fail(errors.New(d.cancelled))
		}
		return c.fail(fmt.Errorf(d.failed, err))
	}
	fmt.Fprintln(c.stderr, d.done)
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
		fmt.Fprintln(c.stderr, "usage: basalt init [--agent NAME] [--remote] [--demo]\n\n"+
			"Installs the engine service when needed, then prints and opens the setup link. Finish the setup on that page:\n"+
			"the admin connection string is typed there, never here.\n\n"+
			"  --agent NAME  the agent's name\n  --remote      on a bot's machine: make a setup code for the connect page\n  --demo        set up the sample database instead of your own tables\n\n"+manyAgentsHelp)
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
	engineWaiting    engineState = iota // no config yet: the setup page installs
	engineSetUp                         // it has a config
	engineRemoved                       // the page removed its last agent
	engineResetAsked                    // the person said the database is not theirs
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
		case err == nil && code == localsetup.CodeResetAsked:
			// A "No" left from an earlier page: the engine is set up, and
			// only the init that opened the page resets it.
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
