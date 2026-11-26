package handoff

import (
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// StoppedFiles are the agent's files a confirmation the engine stopped in
// is finished on.
type StoppedFiles interface {
	// CredentialExists reports whether the agent's credential file exists,
	// not following a link.
	CredentialExists() (bool, error)
	Lock() (unlock func(), err error)
	// RemoveSecret removes .secret; a missing one is not an error.
	RemoveSecret() error
	// ConfirmSetup clears awaitingAddress from pending setup id.
	ConfirmSetup(id string) error
}

// ServesConnectOnly says whether the agent with pending setup is one the
// engine serves with the connect-only runtime: waiting for its address, or
// refused. An agent whose credential file exists with awaitingAddress still
// set is one whose confirmation stopped half way (the engine stopped after
// it wrote the credential): only that YES writes it, so the engine finishes
// it and serves the agent on its credential. As root (asRoot) the engine
// touches none of the agent's files here: a confirmation it stopped in is
// finished by an engine started as the agent's OS user.
func ServesConnectOnly(setup *config.Setup, asRoot bool, files StoppedFiles, log *slog.Logger) (bool, error) {
	if setup == nil || !setup.ConnectOnly() {
		return false, nil
	}
	if setup.Refused || asRoot {
		return true, nil
	}
	exists, err := files.CredentialExists()
	if err != nil {
		return false, err
	}
	if !exists {
		return true, nil
	}
	unlock, err := files.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if err := files.RemoveSecret(); err != nil {
		return false, err
	}
	if err := files.ConfirmSetup(setup.SetupID); err != nil {
		return false, err
	}
	log.Info("finished a confirmed connect-only setup the engine stopped in", "setupId", setup.SetupID)
	return false, nil
}
