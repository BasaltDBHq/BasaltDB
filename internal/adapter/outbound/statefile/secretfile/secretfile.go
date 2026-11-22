// Package secretfile keeps an agent's link secrets (links.Secrets) in
// <stateDir>/<agent>.links.json, mode 0600 (CONTRACT.md, Link secrets).
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// fileMode keeps the hashes to the engine's OS user.
const fileMode = 0o600

// File is the store's file at Path.
type File struct {
	Path string
}

var _ links.Persister = File{}

// Open returns the store persisted at path, loading its unexpired hashes,
// so short links survive an engine restart. A file that cannot be read is
// reported with an empty store that replaces it on the next issue.
func Open(path string, now func() time.Time, rand io.Reader) (*links.Secrets, error) {
	f := File{Path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return links.NewSecretsWith(f, now, rand), nil
	}
	if err != nil {
		return links.NewSecretsWith(f, now, rand), fmt.Errorf("link secrets %s: %w", path, err)
	}
	s, err := links.RestoreSecrets(raw, f, now, rand)
	if err != nil {
		return s, fmt.Errorf("link secrets %s: %w", path, err)
	}
	return s, nil
}

// New is an empty store persisted at path.
func New(path string, now func() time.Time, rand io.Reader) *links.Secrets {
	return links.NewSecretsWith(File{Path: path}, now, rand)
}

// Save writes raw atomically (write, then rename).
func (f File) Save(raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), filepath.Base(f.Path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("link secrets: %w", err)
	}
	defer os.Remove(tmp.Name()) // gone after the rename; best effort otherwise
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("link secrets: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("link secrets: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("link secrets: %w", err)
	}
	return os.Rename(tmp.Name(), f.Path)
}
