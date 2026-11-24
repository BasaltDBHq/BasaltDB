package setupcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/user"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// RunLocal is basalt init on a person-operated engine (CONTRACT.md,
// basalt init, persona 1). It only starts things: it installs the engine
// service through the system's administrator dialog when there is none
// yet, waits for the engine's setup page, then prints the setup link and
// opens it in the browser. The person does the rest on the page. It asks
// nothing in the terminal and never reads the admin connection string.
// The service's fixed scripts and paths come from h.
func RunLocal(c *cli.IO, h LocalHost, args []string) int {
	job, err := parseInitLocal(c, args)
	if errors.Is(err, flag.ErrHelp) {
		return cli.ExitOK
	}
	if err != nil {
		return c.Fail(err)
	}
	if c.Host.Euid() == 0 {
		return c.Fail(fmt.Errorf("%w: run basalt init as your own OS user, not root: the agent runs as that user, and the setup page asks for your password when it needs one", cli.ErrUsage))
	}
	me, err := user.Current()
	if err != nil {
		return c.Fail(fmt.Errorf("your OS user cannot be read: %w", err))
	}
	job.OSUser = me.Username
	installed := c.Host.System(io.Discard, io.Discard).Exists(h.OSUnitPath(c.Goos))
	if err := enginecli.EnsureService(c, h); err != nil {
		return c.Fail(err)
	}
	if installed {
		if err := restartOlderEngine(c, h); err != nil {
			return c.Fail(err)
		}
	}
	state, err := waitForSetupPage(c)
	if err != nil {
		return c.Fail(err)
	}
	switch state {
	case setup.EngineSetUp:
		if code, reset := changeLink(c, h, job); !reset {
			return code
		}
		// The person answered "No, this isn't mine" and reset the engine
		// through the administrator dialog (Not your database): once it
		// waits for a first install, this init goes on to the install link.
		next, err := waitForSetupPage(c)
		if err != nil {
			return c.Fail(err)
		}
		if next != setup.EngineWaiting {
			return c.Fail(errors.New("the engine was set up again before this init could open the install page; run basalt init again"))
		}
	case setup.EngineRemoved:
		return removeEngineService(c, h)
	case setup.EngineWaiting, setup.EngineResetAsked:
		// EngineResetAsked is never the answer here: waitForSetupPage
		// takes a "No" it finds at the start as an engine set up.
	}
	link, err := localsetup.Link(links.DefaultLocal, job)
	if err != nil {
		return c.Fail(err)
	}
	fmt.Fprintln(c.Stdout, link)
	fmt.Fprintln(c.Stdout, "basalt mcp --agent "+job.Agent)
	if err := c.Host.OpenURL(c.Ctx, link); err != nil {
		fmt.Fprintln(c.Stderr, "basalt: the browser did not open; open the link above by hand")
	}
	fmt.Fprintln(c.Stderr, "basalt: finish the setup on the page that opened: type your database's admin connection string there, never here. The last line above is the MCP server the agent registers.")
	return cli.ExitOK
}

// restartOlderEngine restarts the engine service when it runs a different
// build than this basalt: a new binary installed at the service's path is
// not the running engine until the service restarts. The restart is the
// administrator dialog's fixed script; with no dialog init stops and says
// how. An engine that does not answer is left to waitForSetupPage.
func restartOlderEngine(c *cli.IO, h LocalHost) error {
	build, err := c.Host.EngineBuild(c.Ctx, links.DefaultLocal)
	if err != nil {
		// Nothing answers: the engine is starting or down, and the wait
		// for its page says which.
		return nil //nolint:nilerr // an engine that does not answer is not a different build
	}
	if build == buildinfo.Version {
		return nil
	}
	script, err := h.OSRestartScript(c.Goos)
	if err != nil {
		return err
	}
	command := strings.TrimSpace(script)
	if err := c.Host.DialogAvailable(c.Goos); err != nil {
		return fmt.Errorf("the engine service runs a different build of basalt than this one, and restarting it needs the system's administrator dialog, which cannot be shown here (%w). Restart it as root: %s", err, command)
	}
	fmt.Fprintln(c.Stderr, "basalt: the engine service runs a different build than this basalt. Asking for your password in the system's administrator dialog to restart it: it runs "+command)
	if err := c.Host.AdminDialog(c.Ctx, c.Goos, servicespec.RestartPrompt, script, c.Stderr); err != nil {
		if errors.Is(err, servicespec.ErrDialogCancelled) {
			return fmt.Errorf("the administrator dialog was closed, so the engine service was not restarted and still runs a different build. Restart it as root: %s, or run basalt init again", command)
		}
		return fmt.Errorf("the engine service was not restarted: %w. Restart it as root: %s", err, command)
	}
	// The engine is down while it restarts: wait for /healthz to answer
	// before the build is read again, or a not-yet-answering engine would
	// count as a restart that worked.
	again, err := waitForEngineBuild(c)
	if err != nil {
		return fmt.Errorf("the engine service did not answer on %s within %s after the restart (%w). See %s for why, and restart it as root: %s", links.DefaultLocal, restartAnswerWait, err, engine.LogHint(c.Goos), command)
	}
	if again != buildinfo.Version {
		return fmt.Errorf("the engine service was restarted but still runs a different build of basalt than this one: the service starts the binary its unit file names (%s), which is not this basalt. Install this basalt there, or point the unit at it, and restart the service as root: %s", h.OSUnitPath(c.Goos), command)
	}
	fmt.Fprintln(c.Stderr, "basalt: the engine service is restarted onto this build.")
	return nil
}

// restartAnswerWait bounds how long init waits for the engine to answer
// /healthz after the restart.
const restartAnswerWait = 15 * time.Second

// waitForEngineBuild polls the engine's /healthz until it answers, and
// returns the build it reports.
func waitForEngineBuild(c *cli.IO) (string, error) {
	ctx, cancel := context.WithTimeout(c.Ctx, restartAnswerWait)
	defer cancel()
	for {
		build, err := c.Host.EngineBuild(ctx, links.DefaultLocal)
		if err == nil {
			return build, nil
		}
		select {
		case <-ctx.Done():
			return "", err
		case <-time.After(setup.SetupWaitStep):
		}
	}
}

// changeLink is basalt init on an engine that is already set up: it prints
// and opens the setup page's CHANGE link for the agent, where the person
// picks Update or Remove (CONTRACT.md, The local setup page). It prints no
// basalt mcp line: the agent is registered already. reset: the person
// answered "No, this isn't mine" on the page and reset the engine through
// the administrator dialog (Not your database), and init goes on to the
// install.
func changeLink(c *cli.IO, h LocalHost, job localsetup.Job) (code int, reset bool) {
	job.Job, job.Demo = localsetup.JobChange, false
	link, err := localsetup.Link(links.DefaultLocal, job)
	if err != nil {
		return c.Fail(err), false
	}
	fmt.Fprintln(c.Stdout, link)
	if err := c.Host.OpenURL(c.Ctx, link); err != nil {
		fmt.Fprintln(c.Stderr, "basalt: the browser did not open; open the link above by hand")
	}
	fmt.Fprintln(c.Stderr, "basalt: the engine on this computer is already set up. On the page that opened, update the guard or remove BasaltDB: type your database's admin connection string there, never here.")
	switch waitForRemoval(c) {
	case setup.EngineRemoved:
		return removeEngineService(c, h), false
	case setup.EngineResetAsked:
		if code := resetEngineService(c, h); code != cli.ExitOK {
			return code, false
		}
		return cli.ExitOK, true
	case setup.EngineWaiting, setup.EngineSetUp:
	}
	fmt.Fprintln(c.Stderr, "basalt: after a Remove on that page, run basalt init once more: it removes the engine service.")
	return cli.ExitOK, false
}

// waitForRemoval asks the engine, for up to setup.RemovalWait (as long as an
// approval wait), whether the page's Remove deleted engine.json
// (ENGINE_REMOVED, EngineRemoved) or the person answered "No, this isn't
// mine" (RESET_ASKED, EngineResetAsked). Any other answer, an Update
// included, keeps waiting until the time is up (EngineSetUp).
func waitForRemoval(c *cli.IO) setup.BasaltEngineState {
	ctx, cancel := context.WithTimeout(c.Ctx, setup.RemovalWait)
	defer cancel()
	for {
		code, err := c.Host.SetupState(ctx, links.DefaultLocal)
		switch {
		case err == nil && code == localsetup.CodeEngineRemoved:
			return setup.EngineRemoved
		case err == nil && code == localsetup.CodeResetAsked:
			return setup.EngineResetAsked
		}
		select {
		case <-ctx.Done():
			return setup.EngineSetUp
		case <-time.After(setup.RemovalWaitStep):
		}
	}
}

// resetEngineService resets BasaltDB on this computer after the person
// answered "No, this isn't mine" on the setup page, through the
// administrator dialog with its fixed script (service.ResetScript): it
// deletes the engine's config, credentials and pins and restarts the
// service. The person's password is the proof the page cannot give.
func resetEngineService(c *cli.IO, h LocalHost) int {
	return runServiceDialog(c, serviceDialog{
		script:    h.OSResetScript,
		prompt:    servicespec.ResetPrompt,
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
func removeEngineService(c *cli.IO, h LocalHost) int {
	return runServiceDialog(c, serviceDialog{
		script:    h.OSRemoveScript,
		prompt:    servicespec.RemovePrompt,
		noDialog:  "BasaltDB is removed from the database, but the engine service is removed through the system's administrator dialog, which cannot be shown here (%w). Run basalt init again in a desktop session on this machine",
		asking:    "basalt: BasaltDB is removed from the database. Asking for your password in the system's administrator dialog to remove the engine service: it stops the service and removes its files and OS users.",
		cancelled: "the administrator dialog was closed, so the engine service stays. Run basalt init again to remove it",
		failed:    "the engine service was not removed: %w",
		done:      "basalt: the engine service is removed.",
	})
}

// LocalHost is what basalt init on a person-operated engine reaches
// outside the CLI: the engine service's fixed scripts, its unit's path and
// its default OS user.
type LocalHost interface {
	enginecli.InstallHost
	// OSRemoveScript is the fixed script that removes the engine service.
	OSRemoveScript(goos string) (string, error)
	// OSRestartScript is the fixed script that restarts the engine service.
	OSRestartScript(goos string) (string, error)
	// OSResetScript is the fixed script that resets BasaltDB on this
	// computer.
	OSResetScript(goos string) (string, error)
}

// serviceDialog is one fixed script run through the administrator dialog,
// with what init says around it.
type serviceDialog struct {
	script                                            func(goos string) (string, error)
	prompt, noDialog, asking, cancelled, failed, done string
}

func runServiceDialog(c *cli.IO, d serviceDialog) int {
	if err := c.Host.DialogAvailable(c.Goos); err != nil {
		return c.Fail(fmt.Errorf(d.noDialog, err))
	}
	script, err := d.script(c.Goos)
	if err != nil {
		return c.Fail(err)
	}
	fmt.Fprintln(c.Stderr, d.asking)
	if err := c.Host.AdminDialog(c.Ctx, c.Goos, d.prompt, script, c.Stderr); err != nil {
		if errors.Is(err, servicespec.ErrDialogCancelled) {
			return c.Fail(errors.New(d.cancelled))
		}
		return c.Fail(fmt.Errorf(d.failed, err))
	}
	fmt.Fprintln(c.Stderr, d.done)
	return cli.ExitOK
}

// parseInitLocal reads basalt init's flags on a person-operated engine:
// --agent and --demo only. Any other flag is a usage error.
func parseInitLocal(c *cli.IO, args []string) (localsetup.Job, error) {
	fs := cli.NewFlagSet("init")
	fs.SetOutput(c.Stderr)
	agent := fs.String("agent", "", "the agent's name (default: "+setupcode.DemoAgent+")")
	demoFlag := fs.Bool("demo", false, "set up the sample database instead of your own tables")
	fs.Usage = func() {
		fmt.Fprintln(c.Stderr, "usage: basalt init [--agent NAME] [--remote] [--demo]\n\n"+
			"Installs the engine service when needed, then prints and opens the setup link. Finish the setup on that page:\n"+
			"the admin connection string is typed there, never here.\n\n"+
			"  --agent NAME  the agent's name\n  --remote      on a bot's machine: make a setup code for the connect page\n  --demo        set up the sample database instead of your own tables\n\n"+cli.ManyAgentsHelp)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return localsetup.Job{}, err
		}
		return localsetup.Job{}, fmt.Errorf("%w: basalt init on this computer takes only --agent and --demo; the setup page asks for the rest", cli.ErrUsage)
	}
	if fs.NArg() > 0 {
		return localsetup.Job{}, fmt.Errorf("%w: basalt init takes no arguments", cli.ErrUsage)
	}
	name := *agent
	if name == "" {
		name = setupcode.DemoAgent
	}
	if !guardmodel.ValidAgentName(name) {
		return localsetup.Job{}, fmt.Errorf("%w: --agent %q is not a name an agent can have (lowercase letters, digits and _)", cli.ErrUsage, name)
	}
	return localsetup.Job{Job: localsetup.JobInstall, Agent: name, Demo: *demoFlag}, nil
}

// waitForSetupPage waits until the engine answers its setup routes, and
// reads from the answer whether it is waiting for its config. An engine
// service the service manager started again during the wait, after an exit
// with an error, ends the wait at once, naming its log.
func waitForSetupPage(c *cli.IO) (setup.BasaltEngineState, error) {
	ctx, cancel := context.WithTimeout(c.Ctx, setup.SetupWait)
	defer cancel()
	firstRuns := -1
	for {
		code, err := c.Host.SetupState(ctx, links.DefaultLocal)
		switch {
		case err == nil && code == localsetup.CodeJobUnavailable:
			return setup.EngineSetUp, nil
		case err == nil && code == localsetup.CodeEngineRemoved:
			return setup.EngineRemoved, nil
		case err == nil && code == localsetup.CodeResetAsked:
			// A "No" left from an earlier page: the engine is set up, and
			// only the init that opened the page resets it.
			return setup.EngineSetUp, nil
		case err == nil:
			return setup.EngineWaiting, nil
		}
		if runs, last, err := c.Host.ServiceRuns(ctx, c.Goos); err == nil {
			// The counters are the service's whole life: only a start during
			// this wait counts.
			if firstRuns < 0 {
				firstRuns = runs
			}
			if runs > firstRuns && engine.CrashLoops(runs, last) {
				return 0, fmt.Errorf("the engine service keeps stopping: it started %d times and last exited with code %d. See %s for why", runs, last, engine.LogHint(c.Goos))
			}
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("the engine service did not answer on %s within %s; see %s", links.DefaultLocal, setup.SetupWait, engine.LogHint(c.Goos))
		case <-time.After(setup.SetupWaitStep):
		}
	}
}
