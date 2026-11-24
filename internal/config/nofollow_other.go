//go:build !unix

package config

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// openCredential: see nofollow_unix.go. The engine runs on linux and darwin
// only; elsewhere the file is opened as it is.
func openCredential(path string) (*os.File, error) { return os.Open(path) }
