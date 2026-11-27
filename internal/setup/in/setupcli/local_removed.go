package setupcli

import (
	"context"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// The lines basalt init prints on an engine the setup page removed
// (CONTRACT.md, The local setup page, Removing the engine service).
const (
	removedChooseLine = "basalt: BasaltDB was removed from your database. Open this link to choose: finish removing it from this computer, or set it up again."
	removedAgainLine  = "basalt: BasaltDB was removed from your database earlier. Setting up again on this computer's engine."
)

// removedEngine is basalt init on an engine the setup page removed: the
// engine still runs, serving no agent. With --demo it sets up again on that
// engine (install: init goes on to the install link), with no removal and
// no dialog. Without it, init prints and opens the REMOVED link, whose page
// asks the person, and waits: only the page's "Remove it from this
// computer too" runs the removal script, through the administrator dialog.
func removedEngine(c *cli.IO, h LocalHost, job localsetup.Job) (code int, install bool) {
	if job.Demo {
		fmt.Fprintln(c.Stderr, removedAgainLine)
		return cli.ExitOK, true
	}
	job.Job = setup.JobRemoved
	link, err := localsetup.Link(links.DefaultLocal, job)
	if err != nil {
		return c.Fail(err), false
	}
	fmt.Fprintln(c.Stderr, removedChooseLine)
	fmt.Fprintln(c.Stdout, link)
	// The agent registers it either way: "Set up BasaltDB again" on the
	// page serves this agent again.
	fmt.Fprintln(c.Stdout, "basalt mcp --agent "+job.Agent)
	if err := c.Host.OpenURL(c.Ctx, link); err != nil {
		fmt.Fprintln(c.Stderr, "basalt: the browser did not open; open the link above by hand")
	}
	switch waitForChoice(c) {
	case choiceRemove:
		return removeEngineService(c, h), false
	case choiceSetUp:
		fmt.Fprintf(c.Stderr, "basalt: BasaltDB is set up again on this computer. The agent %s can go on.\n", job.Agent)
		return cli.ExitOK, false
	case choiceNone:
	}
	fmt.Fprintln(c.Stderr, "basalt: this init stops waiting. Setting BasaltDB up again on that page needs no more from the agent. To remove it from this computer, run basalt init again and press Remove it from this computer too on the page it opens.")
	return cli.ExitOK, false
}

// choice is what the person picked on the REMOVED link's page.
type choice int

const (
	choiceNone   choice = iota // nothing yet, when the wait is up
	choiceRemove               // "Remove it from this computer too"
	choiceSetUp                // "Set up BasaltDB again", and its install ran
)

// waitForChoice asks the engine, for up to setup.RemovalWait, whether the
// person pressed "Remove it from this computer too" (REMOVE_ASKED) or set
// BasaltDB up again (the engine serves a config: JOB_UNAVAILABLE). Any
// other answer, or none while the engine starts again onto its new
// config, keeps waiting.
func waitForChoice(c *cli.IO) choice {
	ctx, cancel := context.WithTimeout(c.Ctx, setup.RemovalWait)
	defer cancel()
	for {
		code, err := c.Host.SetupState(ctx, links.DefaultLocal, "", time.Time{})
		switch {
		case err == nil && code == setup.CodeRemoveAsked:
			return choiceRemove
		case err == nil && code == setup.CodeJobUnavailable:
			return choiceSetUp
		}
		select {
		case <-ctx.Done():
			return choiceNone
		case <-time.After(setup.RemovalWaitStep):
		}
	}
}
