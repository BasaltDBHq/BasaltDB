//go:build !unix

package main

import (
	"errors"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// errRemoteUnsupported: basalt init --remote runs on linux and darwin only.
var errRemoteUnsupported = errors.New("basalt init --remote is not supported on this platform")

// openRootCredFiles: see errRemoteUnsupported.
func openRootCredFiles(setupFilesHost, string, int) (setup.CredFiles, error) {
	return nil, errRemoteUnsupported
}

// rootConfigDir: see errRemoteUnsupported.
type rootConfigDir struct{}

// openRootConfigDir: see errRemoteUnsupported.
func openRootConfigDir(setupFilesHost, string, int) (*rootConfigDir, error) {
	return nil, errRemoteUnsupported
}

// rootTrustedOwner: see errRemoteUnsupported.
func rootTrustedOwner(string) (int, error) { return 0, errRemoteUnsupported }

func (*rootConfigDir) Upsert(string, config.Settings, config.Agent) (config.VaultWritten, error) {
	return config.VaultWritten{}, errRemoteUnsupported
}

func (*rootConfigDir) update(string, config.Change) error { return errRemoteUnsupported }

func (*rootConfigDir) Close() {}

// rootEngineKey: see errRemoteUnsupported.
func rootEngineKey(setupFilesHost, string, string, *rootConfigDir, func() time.Time) ([]byte, error) {
	return nil, errRemoteUnsupported
}
