package app

import (
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

// runInit: basalt init. --remote makes a setup code for an agent-operated
// engine; without it, init starts the local setup (runInitLocal), which
// never reads the admin connection string. h is what init reaches outside
// the CLI.
func runInit(c *cli.IO, h initHost, args []string) int {
	// --remove on an agent-operated engine (the bot's own computer) prints
	// the connect page's removal link, as --remote does for a setup.
	if setupcli.IsRemote(args) || setupcli.RemovesRemote(c, args) {
		return setupcli.RunRemote(c, h, args)
	}
	return setupcli.RunLocal(c, h, args)
}

// initHost is what basalt init reaches outside the CLI, local and --remote.
type initHost interface {
	setupcli.Host
	setupcli.LocalHost
}
