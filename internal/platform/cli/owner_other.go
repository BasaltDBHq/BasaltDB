//go:build !unix

package cli

import (
	"errors"
	"os"
)

// InfoOwnerUID has no owner to read off unix.
func InfoOwnerUID(os.FileInfo) (int, bool) { return 0, false }

// FileOwnerUID has no owner to read off unix.
func FileOwnerUID(string) (int, error) { return 0, errors.New("file owners are read on unix only") }
