//go:build !unix

package main

import (
	"errors"
	"os"
)

// infoOwnerUID has no owner to read off unix.
func infoOwnerUID(os.FileInfo) (int, bool) { return 0, false }

// fileOwnerUID has no owner to read off unix.
func fileOwnerUID(string) (int, error) { return 0, errors.New("file owners are read on unix only") }
