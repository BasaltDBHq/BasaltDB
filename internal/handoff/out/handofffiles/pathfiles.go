package handofffiles

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// PathFiles reaches an agent's credential file, and for the setup finisher
// its .pending, its .lock and the engine config the finisher clears the
// setup from (handoff.FinishFiles), by path: an engine not running as root (a
// service engine, or a person's own engine), in its user's directories.
type PathFiles struct{ ConfigPath, CredFile string }

// ReadCredential reads the agent's credential file.
func (p PathFiles) ReadCredential() (string, error) { return config.ReadCredential(p.CredFile) }

// ReadPending reads the agent's .pending credential, at most limit bytes.
func (p PathFiles) ReadPending(limit int) (string, os.FileInfo, error) {
	path := p.CredFile + config.PendingSuffix
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return config.ReadOwnCredentialLimit(path, limit)
}

// Promote renames .pending over the credential file, when it is still the
// file ReadPending read.
func (p PathFiles) Promote(pending os.FileInfo) error {
	path := p.CredFile + config.PendingSuffix
	if err := config.SameCredentialFile(path, pending); err != nil {
		return err
	}
	return os.Rename(path, p.CredFile)
}

// Lock takes the agent's .lock.
func (p PathFiles) Lock() (func(), error) { return config.LockFile(p.CredFile + config.LockSuffix) }

// ClearSetup clears setup id of agent from the engine config.
func (p PathFiles) ClearSetup(agent, id string) (bool, error) {
	return config.ClearSetup(p.ConfigPath, agent, id)
}

// Close releases nothing: the files are reached by path.
func (PathFiles) Close() {}
