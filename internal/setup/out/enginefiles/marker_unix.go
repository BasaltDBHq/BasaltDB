//go:build unix

package enginefiles

import (
	"os"
	"syscall"
)

// markerMode is the marker's mode: the engine's own.
const markerMode = 0o600

// CreateMarker creates an empty file at path in place, mode 0600, never
// through a symlink (O_NOFOLLOW).
func (Files) CreateMarker(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, markerMode)
	if err != nil {
		return err
	}
	return f.Close()
}
