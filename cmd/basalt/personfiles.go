package main

import (
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// loadEngineConfig reads the engine config at path for this person CLI.
func loadEngineConfig(c *cli.IO, path string) (config.Config, error) {
	return loadEngineConfigAs(c.Shell, c.Host.Euid(), path)
}

// loadEngineConfigAs reads the engine config at path for a process with
// effective uid euid: config.Load, or as root the hardened read
// (loadConfigAsRoot, opening through sh). basalt engine started as root
// reads its config here too.
func loadEngineConfigAs(sh cli.Host, euid int, path string) (config.Config, error) {
	if euid != 0 {
		return config.Load(path)
	}
	cfg, _, err := loadConfigAsRoot(sh, path)
	return cfg, err
}
