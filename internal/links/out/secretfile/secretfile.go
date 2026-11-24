// Package secretfile keeps an agent's link secrets (links.Secrets) in
// <stateDir>/<agent>.links.json, mode 0600 (CONTRACT.md, Link secrets).
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"

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

// Save writes raw atomically (write, then rename).
func (f File) Save(raw []byte) error {
	if err := atomicfile.Write(f.Path, raw, atomicfile.Options{Mode: fileMode}); err != nil {
		return fmt.Errorf("link secrets: %w", err)
	}
	return nil
}
