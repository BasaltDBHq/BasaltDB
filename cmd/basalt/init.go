package main

import (
	"os"
	"os/user"
)

// runInit: basalt init. --remote makes a setup code for an agent-operated
// engine; without it, init starts the local setup (runInitLocal), which
// never reads the admin connection string. h is what init reaches outside
// the CLI.
func runInit(c *cliIO, h initHost, args []string) int {
	if isRemote(args) {
		return runInitRemote(c, h, args)
	}
	return runInitLocal(c, h, args)
}

// initHost is what basalt init reaches outside the CLI, local and --remote.
type initHost interface {
	remoteHost
	localHost
}

// invokingUser is the person running init: under sudo, the user who ran
// sudo, not root.
func invokingUser() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		return name, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// stateDirName is the engine's state directory next to a per-user config.
const stateDirName = "state"

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"
