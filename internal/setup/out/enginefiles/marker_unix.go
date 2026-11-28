//go:build unix

package enginefiles

import (
	"errors"
	"os"
	"syscall"
)

// markerMode is the marker's mode: the engine's own.
const markerMode = 0o600

// CreateMarker creates an empty file at path in place, mode 0600, never
// through a symlink (O_NOFOLLOW) and never blocking on a FIFO someone put
// there (O_NONBLOCK); anything but a plain file at path is refused.
func (Files) CreateMarker(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, markerMode)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New(path + " is not a plain file")
	}
	if err == nil {
		err = f.Truncate(0)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
