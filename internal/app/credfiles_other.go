//go:build !unix

package app

import "errors"

// openRootFiles: the engine runs on Linux and macOS only.
func openRootFiles(string, string, string) (agentFiles, error) {
	return nil, errors.New("the engine runs on Linux and macOS only")
}
