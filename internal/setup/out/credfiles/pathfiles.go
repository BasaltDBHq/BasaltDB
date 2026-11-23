package credfiles

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// PathCredFiles reaches the credential files by path: init --remote not as
// root, in the user's own directories.
type PathCredFiles struct{}

func (PathCredFiles) Lock(path string) (func(), error) { return lockFile(path) }

func (PathCredFiles) Read(path string) (string, os.FileInfo, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", nil, err
	}
	return readOwnCredential(path)
}

func (PathCredFiles) Stat(path string) (os.FileInfo, error) { return os.Lstat(path) }

func (PathCredFiles) Write(path string, data []byte) error { return config.WriteFile(path, data) }

func (PathCredFiles) Rename(from, to string) error { return os.Rename(from, to) }

func (PathCredFiles) Remove(path string) error { return os.Remove(path) }

func (PathCredFiles) Close() {}
