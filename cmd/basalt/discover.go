package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// systemConfig is the system path of engine.json; tests point it at a
// temporary file.
func (c *cliIO) systemConfig() string {
	return cmp.Or(c.systemConfigPath, config.DefaultPath(c.goos))
}

// pathOverrides point a command at temporary files in tests: the engine
// config, and for init the socket directory and the credential file. The
// zero value finds everything by itself.
type pathOverrides struct{ config, socketDir, credFile string }

// findConfig is the engine.json this command uses ([Config discovery]).
func (c *cliIO) findConfig() (string, error) {
	if c.paths.config != "" {
		return c.paths.config, nil
	}
	return cli.DiscoverConfig(c.host, c.systemConfig())
}

// refuseSecondConfig is the error of a setup that would write the person's
// own engine.json while the system one exists: a second config would make
// every later command stop on two. Root and the tests' path overrides write
// where they are told.
func (c *cliIO) refuseSecondConfig() error {
	if c.host.Euid() == 0 || c.paths.config != "" {
		return nil
	}
	system := c.systemConfig()
	if _, err := os.Stat(system); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("the engine config %s exists already: run basalt init as its owner (with sudo), not as this user", system)
}
