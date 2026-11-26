package handofffiles

import (
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// ProbeCacheFile is the probe cache's file in the engine's state directory
// Dir (handoff.CacheFile), a 0600 file of the engine's user.
type ProbeCacheFile struct{ Dir string }

// ProbeCacheName is the cache's file in the state directory.
const ProbeCacheName = "connect-probe.json"

// cacheDirMode is the state directory's mode when Write makes it.
const cacheDirMode = 0o700

func (f ProbeCacheFile) path() string { return filepath.Join(f.Dir, ProbeCacheName) }

// Read reads the file with the credential file's rules: a regular file
// this user owns, mode 0600, not through a link.
func (f ProbeCacheFile) Read() (string, error) {
	raw, _, err := config.ReadOwnCredential(f.path())
	return raw, err
}

// Write replaces the file with raw, making the state directory when it is
// missing.
func (f ProbeCacheFile) Write(raw []byte) error {
	if err := os.MkdirAll(f.Dir, cacheDirMode); err != nil {
		return err
	}
	return config.WriteFile(f.path(), raw)
}
