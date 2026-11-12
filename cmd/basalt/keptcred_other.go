//go:build !unix

package main

import (
	"errors"
	"os"
)

var errNoService = errors.New("the engine service is not supported on this platform")

// readKeptCredential: the engine service installs on linux and darwin only.
func readKeptCredential(string, string) (string, error) {
	return "", errNoService
}

// openEngineFile: the engine service installs on linux and darwin only.
func openEngineFile(string, string) (*os.File, error) {
	return nil, errNoService
}
