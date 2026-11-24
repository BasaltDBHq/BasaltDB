package handoff

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// AgentFiles reaches an agent's credential file, and for the setup
// finisher its .pending, its .lock and the engine config the finisher
// clears the setup from (FinishFiles): by path (PathFiles) or, started as
// root, through opened directories (the engine's rootFiles).
type AgentFiles interface {
	FinishFiles
	ReadCredential() (string, error)
	Close()
}

// TrustPins writes the pins of trust.d next to engine.json (the setup
// domain's trust directory adapter).
type TrustPins interface {
	// PinNew writes the pin of cert for host, and refuses when a profile
	// covers host, unless that profile is this very pin.
	PinNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error)
	// Repin replaces the engine's own pin for host, never a profile that is
	// not that pin.
	Repin(configPath, host string, cert *x509.Certificate, caOnly bool) ([]string, error)
}

// SetupFiles are a connect-only agent's files as the hand-off reaches
// them, by path (Files): its .secret next to the credential file, the
// credential file the person's YES writes, the agent's lock and its entry
// in engine.json.
type SetupFiles struct {
	ConfigPath, Agent, CredFile string
	// Pins is trust.d next to ConfigPath.
	Pins TrustPins
}

func (f SetupFiles) secretPath() string { return config.SecretPath(f.CredFile, f.Agent) }

// Lock takes the agent's .lock.
func (f SetupFiles) Lock() (func(), error) { return config.LockFile(f.CredFile + LockSuffix) }

// PendingSetup is the agent's pending setup in engine.json now; false when
// none.
func (f SetupFiles) PendingSetup() (config.Setup, bool, error) {
	c, err := config.LoadNoFollow(f.ConfigPath)
	if err != nil {
		return config.Setup{}, false, err
	}
	for _, a := range c.Agents {
		if a.Name == f.Agent && a.Setup != nil {
			return *a.Setup, true, nil
		}
	}
	return config.Setup{}, false, nil
}

// ReadSecret reads .secret with the credential file's rules: a regular
// file this user owns, mode 0600, not through a link.
func (f SetupFiles) ReadSecret() (string, error) {
	secret, _, err := config.ReadOwnCredential(f.secretPath())
	return secret, err
}

// errCredentialExists: the YES never replaces a credential file.
var errCredentialExists = errors.New("the agent already has a credential file")

// WriteCredential writes the agent's credential file; it refuses to replace
// one that exists.
func (f SetupFiles) WriteCredential(dsn string) error {
	if _, err := os.Lstat(f.CredFile); err == nil {
		return fmt.Errorf("%s: %w", f.CredFile, errCredentialExists)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return config.WriteFile(f.CredFile, []byte(dsn+"\n"))
}

// RemoveSecret removes .secret; a missing one is not an error.
func (f SetupFiles) RemoveSecret() error {
	err := os.Remove(f.secretPath())
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove %s: %w", f.secretPath(), err)
}

// ConfirmSetup marks the agent's pending setup id confirmed in engine.json.
func (f SetupFiles) ConfirmSetup(id string) error {
	return f.change(id, func(s *config.Setup) { s.AwaitingAddress = false })
}

// RefuseSetup marks the agent's pending setup id refused in engine.json.
func (f SetupFiles) RefuseSetup(id string) error {
	return f.change(id, func(s *config.Setup) { s.AwaitingAddress, s.Refused = false, true })
}

// MarkAddressInvalid marks the address of the agent's pending setup id
// invalid in engine.json.
func (f SetupFiles) MarkAddressInvalid(id string) error {
	return f.change(id, func(s *config.Setup) { s.AddressInvalid = true })
}

// change edits the agent's pending setup id in engine.json; another setup
// there is a refusal, and nothing is written.
func (f SetupFiles) change(id string, edit func(*config.Setup)) error {
	return config.UpdateConfig(f.ConfigPath, config.Change{Apply: func(c *config.Config) error {
		i := slices.IndexFunc(c.Agents, func(a config.Agent) bool { return a.Name == f.Agent })
		if i < 0 || c.Agents[i].Setup == nil || c.Agents[i].Setup.SetupID != id {
			return fmt.Errorf("engine.json no longer records setup %s for agent %s", id, f.Agent)
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
func (f SetupFiles) WritePin(host string, pin Pin) error {
	_, err := f.Pins.PinNew(f.ConfigPath, host, pin.Top, pin.CAOnly)
	if errors.Is(err, setupcode.ErrCovered) {
		return fmt.Errorf("%w, so the certificate authority trusted on the connect page is not pinned", err)
	}
	return err
}

// RepinSetupFiles are an agent's entry in engine.json and the config's
// trust.d, for a certificateChanged setup (RepinFiles).
type RepinSetupFiles struct {
	SetupFiles
}

// ReplacePin replaces the engine's own pin for host, as the setup page's
// TRUST fix does: never a profile that is not that pin.
func (f RepinSetupFiles) ReplacePin(host string, pin Pin) error {
	_, err := f.Pins.Repin(f.ConfigPath, host, pin.Top, pin.CAOnly)
	return err
}
