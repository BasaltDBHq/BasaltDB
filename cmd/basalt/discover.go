package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// discoverConfig is the engine.json a command finds by itself
// (config.Discover): the one at system, else the one in the person's own
// config directory. root has no per-user config: its engine config is the
// system one.
func discoverConfig(h host, system string) (string, error) {
	user := ""
	if h.Euid() != 0 {
		if base, err := h.UserConfigDir(); err == nil {
			user = config.UserPath(base)
		}
	}
	return config.Discover(system, user)
}

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
	return discoverConfig(c.host, c.systemConfig())
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
