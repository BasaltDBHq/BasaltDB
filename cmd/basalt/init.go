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
	if setupcli.IsRemote(args) {
		return runInitRemote(c, h, args)
	}
	return setupcli.RunLocal(c, h, args)
}

// initHost is what basalt init reaches outside the CLI, local and --remote.
type initHost interface {
	setupcli.Host
	setupcli.LocalHost
}

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"

// runInitRemote: basalt init --remote.
func runInitRemote(c *cli.IO, h setupcli.Host, args []string) int {
	res, err := setupcli.InitRemote(c, h, args)
	if err != nil {
		return c.Fail(err)
	}
	if err := setupcli.PrintRemoteResult(c, res); err != nil {
		return c.Fail(err)
	}
	return cli.ExitOK
}
