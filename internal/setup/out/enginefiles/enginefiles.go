// Package enginefiles reaches the engine's own files for the local setup
// page, by path, as the engine's own user: engine.json and the agents'
// credential files. Each method is the config or os call it is named
// after, unchanged. The setup page refuses an engine that runs as root
// before it reads or writes any of them.
package enginefiles

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// Files has no state.
type Files struct{}

func (Files) Lstat(path string) error {
	_, err := os.Lstat(path)
	return err
}

func (Files) LoadConfig(path string) (config.Config, error) { return config.Load(path) }

func (Files) ReadCredentialFile(path string) (string, error) { return config.ReadCredential(path) }

func (Files) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (Files) WriteFile(path string, data []byte) error { return config.WriteFile(path, data) }

func (Files) Remove(path string) error { return os.Remove(path) }

func (Files) UpsertAgentVault(path string, s config.Settings, a config.Agent) (config.VaultWritten, error) {
	return config.UpsertAgentVault(path, s, a)
}

func (Files) RemoveAgents(path string, names []string) (bool, error) {
	return config.RemoveAgents(path, names)
}
