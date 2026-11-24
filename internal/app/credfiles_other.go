//go:build !unix

package app

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// openRootFiles: the engine runs on Linux and macOS only.
func openRootFiles(string, string, string) (handoff.AgentFiles, error) {
	return nil, errors.New("the engine runs on Linux and macOS only")
}
