// Package configtest writes engine configs for tests.
package configtest

import "github.com/basaltdbhq/basaltdb/internal/config"

// UpsertAgent adds agent a to the config at path, or replaces the agent of
// the same name, creating the file from s when it does not exist. The file is
// written atomically with config.FileMode. basalt init uses
// config.UpsertAgentVault, which also returns the vault it wrote.
func UpsertAgent(path string, s config.Settings, a config.Agent) error {
	_, err := config.UpsertAgentVault(path, s, a)
	return err
}
