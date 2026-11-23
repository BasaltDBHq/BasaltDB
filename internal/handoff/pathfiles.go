package handoff

import (
	"fmt"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// PathFiles reaches an agent's credential file, and for the setup finisher
// its .pending, its .lock and the engine config the finisher clears the
// setup from (FinishFiles), by path: an engine not running as root (a
// service engine, or a person's own engine), in its user's directories.
type PathFiles struct{ ConfigPath, CredFile string }

// ReadCredential reads the agent's credential file.
func (p PathFiles) ReadCredential() (string, error) { return config.ReadCredential(p.CredFile) }

// ReadPending reads the agent's .pending credential, at most limit bytes.
func (p PathFiles) ReadPending(limit int) (string, os.FileInfo, error) {
	path := p.CredFile + PendingSuffix
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return config.ReadOwnCredentialLimit(path, limit)
}

// Promote renames .pending over the credential file, when it is still the
// file ReadPending read.
func (p PathFiles) Promote(pending os.FileInfo) error {
	path := p.CredFile + PendingSuffix
	if err := config.SameCredentialFile(path, pending); err != nil {
		return err
	}
	return os.Rename(path, p.CredFile)
}

// Lock takes the agent's .lock.
func (p PathFiles) Lock() (func(), error) { return config.LockFile(p.CredFile + LockSuffix) }

// ClearSetup clears setup id of agent from the engine config.
func (p PathFiles) ClearSetup(agent, id string) (bool, error) {
	return config.ClearSetup(p.ConfigPath, agent, id)
}

// Close releases nothing: the files are reached by path.
func (PathFiles) Close() {}

// RootCredentialPath is the only credential file an engine running as root
// reads for agent: config.RootCredentialPath, agents/<agent>.url next to
// configPath.
func RootCredentialPath(configPath, agent, named string) (string, error) {
	path, err := config.RootCredentialPath(configPath, agent, named)
	if err != nil {
		return "", fmt.Errorf("%w; as root, basalt engine uses only that path. Fix the agent's store.credentialFile in the config, or start the engine as the agent's user", err)
	}
	return path, nil
}
