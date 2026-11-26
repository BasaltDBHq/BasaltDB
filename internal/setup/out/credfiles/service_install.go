package credfiles

import (
	"errors"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// UpsertedVault is the engine config at configPath with s and a upserted
// (config.UpsertedVault), the existing file opened as root reads the engine
// user's files (OpenEngineFile).
func UpsertedVault(h FilesHost, configPath, engineUser string, s config.Settings, a config.Agent) ([]byte, config.VaultWritten, error) {
	open := func(p string) (*os.File, error) { return OpenEngineFile(h, p, engineUser) }
	return config.UpsertedVault(configPath, open, s, a)
}

// CredentialMissing reports whether no file is at path, not following a
// link.
func CredentialMissing(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}
