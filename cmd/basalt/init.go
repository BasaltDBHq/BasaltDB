package main

import (
	"os"
	"os/user"
	"strings"
)

// runInit: basalt init. --remote makes a setup code for an agent-operated
// engine; without it, init starts the local setup (runInitLocal), which
// never reads the admin connection string. h is what init --remote reaches
// outside the CLI.
func runInit(c *cliIO, h remoteHost, args []string) int {
	if isRemote(args) {
		return runInitRemote(c, h, args)
	}
	return runInitLocal(c, args)
}

// shellQuote quotes s for a POSIX shell when it has anything but plain
// path characters.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
