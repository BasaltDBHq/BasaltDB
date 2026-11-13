package main

import "github.com/basaltdbhq/basaltdb/internal/engine/config"

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
	if c.host.Euid() != 0 {
		cfg, err := config.Load(path)
		return engineConfig{Config: cfg}, err
	}
	cfg, trusted, err := loadConfigAsRoot(path)
	return engineConfig{Config: cfg, asRoot: true, trusted: trusted}, err
}

// credential reads the credential file the config names for an agent.
func (e engineConfig) credential(path string) (string, error) {
	if !e.asRoot {
		return config.ReadCredential(path)
	}
	return readCredentialAsRoot(path, e.trusted, true)
}

// readCredentialFlag reads --credential-file: config.ReadCredential, or
// as root readCredentialAsRoot.
func readCredentialFlag(c *cliIO, path string) (string, error) {
	if c.host.Euid() != 0 {
		return config.ReadCredential(path)
	}
	return readCredentialAsRoot(path, 0, false)
}
