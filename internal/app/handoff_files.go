package app

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
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

func (f handoffFiles) PendingSetup() (config.Setup, bool, error) {
	c, err := config.LoadNoFollow(f.configPath)
	if err != nil {
		return config.Setup{}, false, err
	}
	for _, a := range c.Agents {
		if a.Name == f.agent && a.Setup != nil {
			return *a.Setup, true, nil
		}
	}
	return config.Setup{}, false, nil
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

func (f handoffFiles) MarkAddressInvalid(id string) error {
	return f.change(id, func(s *config.Setup) { s.AddressInvalid = true })
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

// WritePin writes pin for host to trust.d next to engine.json, as basalt
// trust pin does: the person trusted its certificate authority on the
// connect page and the engine's own reading of the chain confirmed it. It
// never replaces trust: when a profile covers host by now, it writes
// nothing, and refuses unless that profile is this very pin.
func (f handoffFiles) WritePin(host string, pin handoff.Pin) error {
	_, err := trustdir.PinNew(f.configPath, host, pin.Top, pin.CAOnly)
	if errors.Is(err, setupcode.ErrCovered) {
		return fmt.Errorf("%w, so the certificate authority trusted on the connect page is not pinned", err)
	}
	return err
}

// repinFiles are an agent's entry in engine.json and the config's trust.d,
// for a certificateChanged setup (handoff.RepinFiles).
type repinFiles struct {
	handoffFiles
}

// ReplacePin replaces the engine's own pin for host, as the setup page's
// TRUST fix does: never a profile that is not that pin.
func (f repinFiles) ReplacePin(host string, pin handoff.Pin) error {
	_, err := trustdir.Repin(f.configPath, host, pin.Top, pin.CAOnly)
	return err
}
