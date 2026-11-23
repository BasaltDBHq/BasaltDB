package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
)

// agentFiles reaches an agent's credential file, and for the setup
// finisher its .pending, its .lock and the engine config the finisher
// clears the setup from (handoff.FinishFiles).
type agentFiles interface {
	handoff.FinishFiles
	readCredential() (string, error)
	close()
}

// pathFiles reaches the files by path: an engine not running as root (a
// service engine, or a person's own engine), in its user's
// directories.
type pathFiles struct{ configPath, credFile string }

func (p pathFiles) readCredential() (string, error) { return config.ReadCredential(p.credFile) }

func (p pathFiles) ReadPending(limit int) (string, os.FileInfo, error) {
	path := p.credFile + handoff.PendingSuffix
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return config.ReadOwnCredentialLimit(path, limit)
}

func (p pathFiles) Promote(pending os.FileInfo) error {
	path := p.credFile + handoff.PendingSuffix
	if err := config.SameCredentialFile(path, pending); err != nil {
		return err
	}
	return os.Rename(path, p.credFile)
}

func (p pathFiles) Lock() (func(), error) { return config.LockFile(p.credFile + handoff.LockSuffix) }

func (p pathFiles) ClearSetup(agent, id string) (bool, error) {
	return config.ClearSetup(p.configPath, agent, id)
}

func (pathFiles) close() {}

// errNotExist reports whether err is a missing file.
func errNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// rootCredentialPath is the only credential file an engine running as root
// reads for agent: config.RootCredentialPath, agents/<agent>.url next to
// configPath.
func rootCredentialPath(configPath, agent, named string) (string, error) {
	path, err := config.RootCredentialPath(configPath, agent, named)
	if err != nil {
		return "", fmt.Errorf("%w; as root, basalt engine uses only that path. Fix the agent's store.credentialFile in the config, or start the engine as the agent's user", err)
	}
	return path, nil
}
