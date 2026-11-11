//go:build !unix

package main

import "errors"

// readKeptCredential: the engine service installs on linux and darwin only.
func readKeptCredential(string, string) (string, error) {
	return "", errors.New("the engine service is not supported on this platform")
}
