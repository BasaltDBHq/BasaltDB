//go:build !unix

package main

import "errors"

// fileOwnerUID has no owner to read off unix.
func fileOwnerUID(string) (int, error) { return 0, errors.New("file owners are read on unix only") }
