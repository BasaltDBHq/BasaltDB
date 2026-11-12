//go:build !unix

package main

import (
	"errors"
	"os"
)

// errRemoteUnsupported: basalt init --remote runs on linux and darwin only.
var errRemoteUnsupported = errors.New("basalt init --remote is not supported on this platform")

// readKeptCredential: the engine service installs on linux and darwin only.
func readKeptCredential(string, string) (string, error) {
	return "", errors.New("the engine service is not supported on this platform")
}

// readOwnCredential: see errRemoteUnsupported.
func readOwnCredential(string) (string, os.FileInfo, error) {
	return "", nil, errRemoteUnsupported
}

// lockFile: see errRemoteUnsupported.
func lockFile(string) (func(), error) {
	return nil, errRemoteUnsupported
}
