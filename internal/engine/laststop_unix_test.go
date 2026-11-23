//go:build unix

package engine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadLastStopRefusesASymlinkAndAFifo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"reason":"x","at":"2026-11-20T01:02:03Z"}`), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, LastStopFile)))
	_, ok := ReadLastStop(dir)
	require.False(t, ok, "a symlink is not the record")
	require.NoError(t, os.Remove(filepath.Join(dir, LastStopFile)))
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, LastStopFile), 0o600))
	_, ok = ReadLastStop(dir)
	require.False(t, ok, "a pipe is not the record and does not block")
}
