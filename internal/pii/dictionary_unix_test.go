//go:build unix

package pii_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// Someone else's hand on the engine's files is an error at open, not a
// rebuild: a link in place of the file or the directory, a file others can
// read, a directory others can write.
func TestDictionaryRefusesUnsafeFiles(t *testing.T) {
	k := newKeys(t, testMaster)
	built := func(t *testing.T) (string, string) {
		t.Helper()
		stateDir := t.TempDir()
		d := openDict(t, stateDir, k, dictOptions())
		require.NoError(t, buildWith(t, d, []value{{pii.EntityEmail, "fixture.alice.tamm@example.com", ""}}))
		require.NoError(t, d.Close())
		return stateDir, filepath.Join(stateDir, "pii", "dictionary.bin")
	}
	open := func(stateDir string) error {
		d, err := pii.OpenDictionary(stateDir, k, dictOptions())
		if err == nil {
			_ = d.Close()
		}
		return err
	}

	t.Run("file is a link", func(t *testing.T) {
		stateDir, path := built(t)
		moved := filepath.Join(t.TempDir(), "elsewhere.bin")
		require.NoError(t, os.Rename(path, moved))
		require.NoError(t, os.Symlink(moved, path))
		require.ErrorContains(t, open(stateDir), "regular file")
	})
	t.Run("file readable by others", func(t *testing.T) {
		stateDir, path := built(t)
		require.NoError(t, os.Chmod(path, 0o644))
		require.ErrorContains(t, open(stateDir), "0600")
	})
	t.Run("file is a directory", func(t *testing.T) {
		stateDir, path := built(t)
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Mkdir(path, 0o700))
		require.ErrorContains(t, open(stateDir), "regular file")
	})
	t.Run("directory writable by others", func(t *testing.T) {
		stateDir, _ := built(t)
		require.NoError(t, os.Chmod(filepath.Join(stateDir, "pii"), 0o777))
		require.ErrorContains(t, open(stateDir), "0755")
	})
	t.Run("directory is a link", func(t *testing.T) {
		stateDir := t.TempDir()
		target := t.TempDir()
		require.NoError(t, os.Symlink(target, filepath.Join(stateDir, "pii")))
		require.ErrorContains(t, open(stateDir), "not a link")
	})
	t.Run("umask does not narrow the directory", func(t *testing.T) {
		stateDir := t.TempDir()
		require.NoError(t, open(stateDir))
		requireMode(t, filepath.Join(stateDir, "pii"), 0o755)
	})
}
