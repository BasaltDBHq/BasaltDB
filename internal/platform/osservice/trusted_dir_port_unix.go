//go:build unix

package osservice

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// TrustedDirPort is a TrustedDir as the setup adapter's port takes it
// (credfiles.TrustedDir): an alias of the interface itself, so the two
// packages name the same type with no import of each other.
type TrustedDirPort = interface {
	config.Dir
	CreateFile(name string, data []byte, mode os.FileMode, owner int) error
	Remove(name string) error
	Close() error
}

// OpenTrustedDirPort is OpenTrustedDir as a TrustedDirPort: no directory
// (a nil interface) with its error.
func OpenTrustedDirPort(dir string, owner int, create bool) (TrustedDirPort, error) {
	d, err := OpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}
