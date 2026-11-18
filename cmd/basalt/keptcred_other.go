//go:build !unix

package main

import (
	"errors"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// errRemoteUnsupported: basalt init --remote runs on linux and darwin only.
var errRemoteUnsupported = errors.New("basalt init --remote is not supported on this platform")

// errNoService: the engine service installs on linux and darwin only.
var errNoService = errors.New("the engine service is not supported on this platform")

// readKeptCredential: the engine service installs on linux and darwin only.
func readKeptCredential(string, string) (string, error) {
	return "", errNoService
}

// openEngineFile: the engine service installs on linux and darwin only.
func openEngineFile(string, string) (*os.File, error) {
	return nil, errNoService
}

// readOwnCredential: see errRemoteUnsupported.
func readOwnCredential(string) (string, os.FileInfo, error) {
	return "", nil, errRemoteUnsupported
}

// lockFile: see errRemoteUnsupported.
func lockFile(string) (func(), error) {
	return nil, errRemoteUnsupported
}

// openRootCredFiles: see errRemoteUnsupported.
func openRootCredFiles(string, int) (credFiles, error) {
	return nil, errRemoteUnsupported
}

// rootConfigDir: see errRemoteUnsupported.
type rootConfigDir struct{}

// openRootConfigDir: see errRemoteUnsupported.
func openRootConfigDir(string, int) (*rootConfigDir, error) { return nil, errRemoteUnsupported }

// rootTrustedOwner: see errRemoteUnsupported.
func rootTrustedOwner(string) (int, error) { return 0, errRemoteUnsupported }

func (*rootConfigDir) upsert(string, config.Settings, config.Agent) (config.VaultWritten, error) {
	return config.VaultWritten{}, errRemoteUnsupported
}

func (*rootConfigDir) update(string, config.Change) error { return errRemoteUnsupported }

func (*rootConfigDir) close() {}

// rootEngineKey: see errRemoteUnsupported.
func rootEngineKey(string, string, *rootConfigDir, func() time.Time) ([]byte, error) {
	return nil, errRemoteUnsupported
}
