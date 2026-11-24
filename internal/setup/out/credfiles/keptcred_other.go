//go:build !unix

package credfiles

import (
	"errors"
	"os"
)

// errRemoteUnsupported: basalt init --remote runs on linux and darwin only.
var errRemoteUnsupported = errors.New("basalt init --remote is not supported on this platform")

// errNoService: the engine service installs on linux and darwin only.
var errNoService = errors.New("the engine service is not supported on this platform")

// ReadKeptCredential: the engine service installs on linux and darwin only.
func ReadKeptCredential(FilesHost, string, string) (string, error) {
	return "", errNoService
}

// OpenEngineFile: the engine service installs on linux and darwin only.
func OpenEngineFile(FilesHost, string, string) (*os.File, error) {
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
