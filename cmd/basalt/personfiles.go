package main

import "github.com/basaltdbhq/basaltdb/internal/config"

// engineConfig is the engine config the person CLI reads in same-user
// mode: config.Load, or as root loadConfigAsRoot. trusted is the user
// the agents' credential files must belong to when root reads them.
type engineConfig struct {
	config.Config
	asRoot  bool
	trusted int
}

// loadEngineConfig reads the engine config at path for this person CLI.
func loadEngineConfig(c *cliIO, path string) (engineConfig, error) {
	return loadEngineConfigAs(c.host.Euid(), path)
}

// loadEngineConfigAs reads the engine config at path for a process with
// effective uid euid: config.Load, or as root the hardened read
// (loadConfigAsRoot). basalt engine started as root reads
// its config here too.
func loadEngineConfigAs(euid int, path string) (engineConfig, error) {
	if euid != 0 {
		cfg, err := config.Load(path)
		return engineConfig{Config: cfg}, err
	}
	cfg, trusted, err := loadConfigAsRoot(path)
	return engineConfig{Config: cfg, asRoot: true, trusted: trusted}, err
}
