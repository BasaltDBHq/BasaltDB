//go:build !unix

package main

import "github.com/basaltdbhq/basaltdb/internal/engine/config"

// loadConfigAsRoot: there is no root on this platform; Load as any user.
func loadConfigAsRoot(path string) (config.Config, int, error) {
	cfg, err := config.Load(path)
	return cfg, 0, err
}

// readCredentialAsRoot: there is no root on this platform; ReadCredential
// as any user.
func readCredentialAsRoot(path string, _ int, _ bool) (string, error) {
	return config.ReadCredential(path)
}
