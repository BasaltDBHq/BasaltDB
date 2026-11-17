//go:build !unix

package binwatch

import (
	"errors"
	"os"
)

// Stat without inodes: size, time and mode only.
func (OS) Stat(path string) (Identity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Size: fi.Size(), ModNanos: fi.ModTime().UnixNano(), Mode: uint32(fi.Mode())}, nil
}

// Exec is not supported off Unix, where the engine does not run.
func Exec(string, []string, []string) error {
	return errors.New("restarting onto a new binary needs Unix")
}
