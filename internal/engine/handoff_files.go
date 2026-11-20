package engine

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// handoffFiles are a connect-only agent's files as the hand-off reaches
// them, by path (handoff.Files): its .secret next to the credential file,
// the credential file the person's YES writes, the agent's lock and its
// entry in engine.json.
type handoffFiles struct {
	configPath, agent, credFile string
}

func (f handoffFiles) secretPath() string { return config.SecretPath(f.credFile, f.agent) }

func (f handoffFiles) Lock() (func(), error) { return config.LockFile(f.credFile + lockSuffix) }

func (f handoffFiles) PendingSetup() (*config.Setup, error) {
	c, err := config.LoadNoFollow(f.configPath)
	if err != nil {
		return nil, err
	}
	for _, a := range c.Agents {
		if a.Name == f.agent {
			return a.Setup, nil
		}
	}
	return nil, nil
}

// ReadSecret reads .secret with the credential file's rules: a regular
// file this user owns, mode 0600, not through a link.
func (f handoffFiles) ReadSecret() (string, error) {
	secret, _, err := config.ReadOwnCredential(f.secretPath())
	return secret, err
}

// errCredentialExists: the YES never replaces a credential file.
var errCredentialExists = errors.New("the agent already has a credential file")

func (f handoffFiles) WriteCredential(dsn string) error {
	if _, err := os.Lstat(f.credFile); err == nil {
		return fmt.Errorf("%s: %w", f.credFile, errCredentialExists)
	} else if !errNotExist(err) {
		return err
	}
	return config.WriteFile(f.credFile, []byte(dsn+"\n"))
}

func (f handoffFiles) RemoveSecret() error {
	err := os.Remove(f.secretPath())
	if err == nil || errNotExist(err) {
		return nil
	}
	return fmt.Errorf("remove %s: %w", f.secretPath(), err)
}

func (f handoffFiles) ConfirmSetup(id string) error {
	return f.change(id, func(s *config.Setup) { s.AwaitingAddress = false })
}

func (f handoffFiles) RefuseSetup(id string) error {
	return f.change(id, func(s *config.Setup) { s.AwaitingAddress, s.Refused = false, true })
}

// change edits the agent's pending setup id in engine.json; another setup
// there is a refusal, and nothing is written.
func (f handoffFiles) change(id string, edit func(*config.Setup)) error {
	return config.UpdateConfig(f.configPath, config.Change{Apply: func(c *config.Config) error {
		i := slices.IndexFunc(c.Agents, func(a config.Agent) bool { return a.Name == f.agent })
		if i < 0 || c.Agents[i].Setup == nil || c.Agents[i].Setup.SetupID != id {
			return fmt.Errorf("engine.json no longer records setup %s for agent %s", id, f.agent)
		}
		edit(c.Agents[i].Setup)
		return nil
	}})
}
