//go:build unix

package engineos

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
	record := filepath.Join(dir, "last-stop.json")
	require.NoError(t, os.Symlink(target, record))
	_, ok := OS{}.ReadLastStop(record)
	require.False(t, ok, "a symlink is not the record")
	require.NoError(t, os.Remove(record))
	require.NoError(t, syscall.Mkfifo(record, 0o600))
	_, ok = OS{}.ReadLastStop(record)
	require.False(t, ok, "a pipe is not the record and does not block")
}
