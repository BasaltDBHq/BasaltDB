//go:build !unix

package app

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// removeEngineFiles: the engine runs on Linux and macOS only.
func removeEngineFiles(config.Config, string, string) error {
	return errors.New("the engine removes itself on Linux and macOS only")
}
