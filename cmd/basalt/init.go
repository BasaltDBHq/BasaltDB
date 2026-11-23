package main

import (
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

// runInit: basalt init. --remote makes a setup code for an agent-operated
// engine; without it, init starts the local setup (runInitLocal), which
// never reads the admin connection string. h is what init reaches outside
// the CLI.
func runInit(c *cli.IO, h initHost, args []string) int {
	if isRemote(args) {
		return runInitRemote(c, h, args)
	}
	return setupcli.RunLocal(c, h, args)
}

// initHost is what basalt init reaches outside the CLI, local and --remote.
type initHost interface {
	remoteHost
	setupcli.LocalHost
}

// stateDirName is the engine's state directory next to a per-user config.
const stateDirName = "state"

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"
