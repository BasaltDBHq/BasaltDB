package app

import (
	"errors"
	"io/fs"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// agentFiles reaches an agent's credential file, and for the setup
// finisher its .pending, its .lock and the engine config the finisher
// clears the setup from (handoff.FinishFiles): by path (handoff.PathFiles)
// or, started as root, through opened directories (rootFiles).
type agentFiles interface {
	handoff.FinishFiles
	ReadCredential() (string, error)
	Close()
}

// errNotExist reports whether err is a missing file.
func errNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
